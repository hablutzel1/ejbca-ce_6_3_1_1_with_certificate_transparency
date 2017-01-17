package org.cesecore.certificates.certificatetransparency;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.certificatetransparency.ctlog.LogInfo;
import org.certificatetransparency.ctlog.LogSignatureVerifier;
import org.certificatetransparency.ctlog.comm.HttpLogClient;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.serialization.Deserializer;
import org.certificatetransparency.ctlog.serialization.DeserializerExporter;
import org.certificatetransparency.ctlog.serialization.Serializer;
import org.cesecore.certificates.certificateprofile.CertificateProfile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

// TODO research about 'ct.fastfail.enabled' and 'ct.fastfail.backoff' 'cesecore.properties' settings, see too 'clearCaches()' which is used by 'org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionBean.clearCTFailFastCache'. Determine if these properties are only meant to be used when OCSP is to be used to transport SCTs.
public class CertificateTransparencyImpl implements CertificateTransparency {

    private static final Logger log = Logger.getLogger(CertificateTransparencyImpl.class);

    private static final int MAX_SCT_LENGTH = (1 << 16) - 1;
    private static final int MAX_SCT_LIST_LENGTH = (1 << 16) - 1;

    private static final String PRECERT_POISON_OID = "1.3.6.1.4.1.11129.2.4.3";

    @Override
    public byte[] fetchSCTList(List<Certificate> chain, CertificateProfile certProfile, Map<Integer, CTLogInfo> configuredCTLogs) throws CTLogException {
        if (certProfile.getCTMinSCTs() == 0) { // Supported by EJBCA, but illegal in RFC 6962.
            throw new IllegalStateException("Minimum number of SCTs == 0 is illegal, please fix in certificate profile configuration.");
        }

        LinkedHashMap<Integer, Ct.SignedCertificateTimestamp> retrievedSCTs = new LinkedHashMap<Integer, Ct.SignedCertificateTimestamp>();
        int maxRetries = certProfile.getCTMaxRetries();
        outer:
        for (int tryIdx = 0; tryIdx < maxRetries + 1; tryIdx++) {
            Set<Integer> enabledCTLogs = certProfile.getEnabledCTLogs();
            for (final Map.Entry<Integer, CTLogInfo> entry : configuredCTLogs.entrySet()) {
                Integer ctLogInfoId = entry.getKey();
                if (enabledCTLogs.contains(ctLogInfoId) && !retrievedSCTs.containsKey(ctLogInfoId)) {
                    CTLogInfo ctLogInfo = entry.getValue();
                    String logURL = ctLogInfo.getUrl();
                    HttpLogClient client = new HttpLogClient(logURL + "ct/v1/", new CustomHttpInvoker(ctLogInfo.getTimeout()));
                    try {
                        Ct.SignedCertificateTimestamp sct = client.addCertificate(chain);
                        PublicKey logPublicKey = ctLogInfo.getLogPublicKey();
                        LogInfo logInfo = new LogInfo(logPublicKey);
                        LogSignatureVerifier logSignatureVerifier = new LogSignatureVerifier(logInfo);
                        if (logSignatureVerifier.verifySignature(sct, chain)) {
                            retrievedSCTs.put(ctLogInfoId, sct);
                            if (retrievedSCTs.size() == certProfile.getCTMaxSCTs()) {
                                break outer;
                            }
                        } else { // Bad signature, just log.
                            // TODO look for an API to simplify encoding a chain to PEM.
                            StringWriter pemStringWriter = new StringWriter();
                            PemWriter pemWriter = new PemWriter(pemStringWriter);
                            for (Certificate certificate : chain) {
                                pemWriter.writeObject(new JcaMiscPEMGenerator(certificate));
                            }
                            pemWriter.flush();
                            log.error("Error verifying SCT signature, log_url: " + logURL + ", sct: " + Base64.encodeBase64String(Serializer.serializeSctToBinary(sct)) + ", precert_chain: " + pemStringWriter + ".");
                        }

                    } catch (Exception e) {
                        log.warn("Error processing SCT from " + logURL + ".", e);
                    }
                }
            }
        }

        if (retrievedSCTs.size() < certProfile.getCTMinSCTs()) {
            throw new CTLogException("Minimum number of SCTs not satisfied.");
        }

        // All right, proceed with serialization.
        ByteArrayOutputStream serializedSCTs = new ByteArrayOutputStream();
        for (Ct.SignedCertificateTimestamp sct : retrievedSCTs.values()) {
            byte[] serializedSCT = Serializer.serializeSctToBinary(sct);
            Serializer.writeVariableLength(serializedSCTs, serializedSCT, MAX_SCT_LENGTH);
        }
        ByteArrayOutputStream signedCertificateTimestampList = new ByteArrayOutputStream();
        Serializer.writeVariableLength(signedCertificateTimestampList, serializedSCTs.toByteArray(), MAX_SCT_LIST_LENGTH);
        return signedCertificateTimestampList.toByteArray();
    }

    @Override
    public byte[] fetchSCTList(List<Certificate> chain, CertificateProfile certProfile, Map<Integer, CTLogInfo> configuredCTLogs, UsageMode usageMode) throws CTLogException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] fetchSCTList(List<Certificate> chain, Collection<CTLogInfo> ctlogs, int minSCTs, int maxSCTs, int maxRetries) throws CTLogException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addPreCertPoison(X509v3CertificateBuilder precertbuilder) {
        try {
            precertbuilder.addExtension(new ASN1ObjectIdentifier(PRECERT_POISON_OID), true, DERNull.INSTANCE);
        } catch (CertIOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public boolean hasSCTs(Certificate cert) {
        byte[] extValueBytes = ((X509Certificate) cert).getExtensionValue(SCTLIST_OID);
        if (extValueBytes == null) {
            return false;
        }
        ASN1OctetString extValue = DEROctetString.getInstance(extValueBytes);
        ASN1OctetString sctListOctetString = DEROctetString.getInstance(extValue.getOctets());
        byte[] sctListValue = DeserializerExporter.readVariableLength(new ByteArrayInputStream(sctListOctetString.getOctets()), MAX_SCT_LIST_LENGTH);
        byte[] firstSerializedSCT = DeserializerExporter.readVariableLength(new ByteArrayInputStream(sctListValue), MAX_SCT_LENGTH);
        Ct.SignedCertificateTimestamp firstSCT = Deserializer.parseSCTFromBinary(new ByteArrayInputStream(firstSerializedSCT));
        // If we got here we have at least one SCT (if any of the previous parsing/deserializing operations fail an exception will be thrown to warn about that exceptional condition).
        return true;
    }

    @Override
    public void clearCaches() {
        // Not supported, but not throwing a UOE to allow the current cache clearing operations to continue normally.
        log.info("org.cesecore.certificates.certificatetransparency.CertificateTransparencyImpl.clearCaches not supported in this version.");
    }

}
