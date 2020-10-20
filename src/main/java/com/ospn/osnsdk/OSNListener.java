package com.ospn.osnsdk;

import com.ospn.osnsdk.data.FriendInfo;
import com.ospn.osnsdk.data.FriendRequest;
import com.ospn.osnsdk.data.GroupInfo;
import com.ospn.osnsdk.data.MessageInfo;
import com.ospn.osnsdk.data.UserInfo;

import java.util.List;

public interface OSNListener {
    void onConnectSuccess ();
    void onConnectFailed (String error);
    void onRecvTextMessage (List<MessageInfo> msgList);
    void onFriendRequest(FriendRequest request);
    void onFriendUpdate(List<FriendInfo> userIDList);
    void onUserUpdate(UserInfo userInfo, List<String> keys);
    void onGroupUpdate(String state, GroupInfo groupInfo, List<String> keys);
}
