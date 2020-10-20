package com.ospn.osnsdk;

public interface OSNGeneralCallbackT<T> {
    void onFailure(String error);
    void onSuccess(T t);
}
