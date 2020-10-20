package com.ospn.osnsdk.data;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class GroupInfo {
    public String groupID;
    public String name;
    public String privateKey;
    public String owner;
    public String portrait;
    public List<MemberInfo> userList;

    public GroupInfo(){
        userList = new ArrayList<>();
    }
    public static GroupInfo toGroupInfo(JSONObject json){
        GroupInfo groupInfo = new GroupInfo();
        groupInfo.groupID = json.getString("groupID");
        groupInfo.name = json.getString("name");
        groupInfo.privateKey = "";
        groupInfo.owner = json.getString("owner");
        groupInfo.portrait = json.getString("portrait");
        JSONArray array = json.getJSONArray("userList");
        if(array != null) {
            for (Object o : array) {
                JSONObject m = (JSONObject) o;
                MemberInfo memberInfo = new MemberInfo();
                memberInfo.osnID = m.getString("osnID");
                memberInfo.groupID = m.getString("groupID");
                memberInfo.state = m.getIntValue("state");
                groupInfo.userList.add(memberInfo);
            }
        }
        return groupInfo;
    }
}
