package com.ospn.osnsdk;

import com.alibaba.fastjson.JSONObject;

public interface SYNCallback {
    void onCallback(String id, JSONObject json);
}
