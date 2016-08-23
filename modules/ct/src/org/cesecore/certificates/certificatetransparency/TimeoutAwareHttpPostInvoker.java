package org.cesecore.certificates.certificatetransparency;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.certificatetransparency.ctlog.comm.HttpPostInvoker;
import org.certificatetransparency.ctlog.comm.LogCommunicationException;

import java.io.IOException;

// TODO check for opportunities to reuse for performance.
class TimeoutAwareHttpPostInvoker extends HttpPostInvoker {

    private final int timeout;

    TimeoutAwareHttpPostInvoker(int timeout) {
        this.timeout = timeout;
    }

    @Override
    public String makePostRequest(String url, String jsonPayload) {
        HttpClient httpClient = new DefaultHttpClient();
        HttpParams httpParams = httpClient.getParams();
        HttpConnectionParams.setConnectionTimeout(httpParams, timeout);
        HttpConnectionParams.setSoTimeout(httpParams, timeout);
        try {
            HttpPost post = new HttpPost(url);
            post.setEntity(new StringEntity(jsonPayload, "utf-8"));
            post.addHeader("Content-Type", "application/json; charset=utf-8");
            return httpClient.execute(post, new BasicResponseHandler());
        } catch (IOException e) {
            throw new LogCommunicationException("Error making POST request to " + url, e);
        } finally {
            httpClient.getConnectionManager().shutdown();
        }
    }

}
