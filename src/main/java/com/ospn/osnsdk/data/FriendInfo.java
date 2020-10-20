package com.ospn.osnsdk.data;

import com.alibaba.fastjson.JSONObject;

public class FriendInfo {
    public String userID;
    public String friendID;
    public int state; //"0, normal; 1, deleted; 2, blacked"

    public static final int Normal = 0;
    public static final int Deleted = 1;
    public static final int Blacked = 2;

    public static FriendInfo toFriendInfo(JSONObject json){
        FriendInfo friendInfo = new FriendInfo();
        friendInfo.state = json.getIntValue("state");
        friendInfo.userID = json.getString("userID");
        friendInfo.friendID = json.getString("friendID");
        return friendInfo;
    }
}
