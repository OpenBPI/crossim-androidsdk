package com.ospn.osnsdk;

public interface OSNGeneralCallback {
    void onSuccess(String json);
    void onFailure(String error);
}
