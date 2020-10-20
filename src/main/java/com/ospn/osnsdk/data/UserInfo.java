package com.ospn.osnsdk.data;

import com.alibaba.fastjson.JSONObject;

public class UserInfo {
    public String userID;
    public String name;
    public String displayName;
    public String portrait;

    public static UserInfo toUserInfo(JSONObject json){
        UserInfo userInfo = new UserInfo();
        userInfo.userID = json.getString("userID");
        userInfo.name = json.getString("name");
        userInfo.displayName = json.getString("displayName");
        userInfo.portrait = json.getString("portrait");
        return userInfo;
    }
}
