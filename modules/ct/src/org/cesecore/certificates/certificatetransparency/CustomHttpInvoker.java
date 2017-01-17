package org.cesecore.certificates.certificatetransparency;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.certificatetransparency.ctlog.comm.HttpInvoker;
import org.certificatetransparency.ctlog.comm.LogCommunicationException;

import java.io.IOException;

// TODO check for opportunities to reuse for performance.
class CustomHttpInvoker extends HttpInvoker {

    private final int timeout;

    CustomHttpInvoker(int timeout) {
        this.timeout = timeout;
    }

    @Override
    public String makePostRequest(String url, String jsonPayload) {
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        // To allow Commons HttpClient to use 'https.protocols' system property (https://blogs.oracle.com/java-platform-group/entry/diagnosing_tls_ssl_and_https).
        httpClientBuilder = httpClientBuilder.useSystemProperties();
        httpClientBuilder.setDefaultRequestConfig(RequestConfig.custom().setConnectTimeout(timeout).setSocketTimeout(timeout).build());
        try (CloseableHttpClient httpClient = httpClientBuilder.build()) {
            HttpPost post = new HttpPost(url);
            post.setEntity(new StringEntity(jsonPayload, "utf-8"));
            post.addHeader("Content-Type", "application/json; charset=utf-8");

            return httpClient.execute(post, new BasicResponseHandler());
        } catch (IOException e) {
            throw new LogCommunicationException("Error making POST request to " + url, e);
        }
    }
}
