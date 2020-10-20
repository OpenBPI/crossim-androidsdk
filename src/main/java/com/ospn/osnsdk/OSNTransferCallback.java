package com.ospn.osnsdk;

public interface OSNTransferCallback {
    void onSuccess(String data);
    void onProgress(long progress, long total);
    void onFailure(String error);
}

