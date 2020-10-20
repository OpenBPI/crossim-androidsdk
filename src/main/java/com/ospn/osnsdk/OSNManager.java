package com.ospn.osnsdk;

import android.content.Context;
import android.content.SharedPreferences;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.ospn.osnsdk.data.FriendInfo;
import com.ospn.osnsdk.data.FriendRequest;
import com.ospn.osnsdk.data.GroupInfo;
import com.ospn.osnsdk.data.MemberInfo;
import com.ospn.osnsdk.data.MessageInfo;
import com.ospn.osnsdk.data.UserInfo;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class OSNManager {
    private String mOsnID = null;
    private String mOsnKey = null;
    private String mServiceID = null;
    private String mAesKey = null;
    private boolean mLogined = false;
    private long mMsgSync = 0;
    private long mCacheSync = 0;
    private String mHost = null;
    private Socket mSock = null;
    private OSNListener mOsnListener;
    private final Object mSendLock = new Object();
    private final Map<String,SYNCallback> mIDMap = new HashMap<>();
    private final ExecutorService mExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
    private SharedPreferences mSp = null;
    private static OSNManager INST = null;

    class Worker implements Runnable{
        public JSONObject json;
        @Override
        public void run() {
            try {
                OsnUtils.logInfo(json.getString("command") + ": " + json.toString());
                byte[] jsonData = json.toString().getBytes();
                byte[] headData = new byte[4];
                headData[0] = (byte) ((jsonData.length >> 24) & 0xff);
                headData[1] = (byte) ((jsonData.length >> 16) & 0xff);
                headData[2] = (byte) ((jsonData.length >> 8) & 0xff);
                headData[3] = (byte) (jsonData.length & 0xff);
                synchronized (mSendLock) {
                    OutputStream outputStream = mSock.getOutputStream();
                    outputStream.write(headData);
                    outputStream.write(jsonData);
                    outputStream.flush();
                }
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
    }
    private void sendPackage(JSONObject json){
        try{
            if(!mSock.isConnected())
                return;
            Worker worker = new Worker();
            worker.json = (JSONObject)json.clone();
            mExecutor.execute(worker);
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    private JSONObject sendPackage(JSONObject json, OSNGeneralCallback callback){
        try{
            if(!mSock.isConnected())
                return null;

            String id = String.valueOf(System.currentTimeMillis());
            json.put("id", id);

            Worker worker = new Worker();
            worker.json = (JSONObject)json.clone();
            mExecutor.execute(worker);

            final Object lock = new Object();
            final JSONObject[] result = {null};
            SYNCallback synCallback = (id1, json1) -> {
                try {
                    result[0] = json1;
                }
                catch (Exception e){
                    e.printStackTrace();
                }
                synchronized (lock) {
                    lock.notify();
                }
            };
            synchronized (mIDMap){
                mIDMap.put(id, synCallback);
            }
            if(callback != null) {
                new Thread(()->{
                    synchronized (lock) {
                        String error = null;
                        try {
                            lock.wait(5000);
                            synchronized (mIDMap){
                                mIDMap.remove(id);
                            }
                            callback.onSuccess(result[0] == null ? null : result[0].toString());
                            return;
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                            error = e.toString();
                        }
                        callback.onFailure(error);
                    }
                }).start();
                return null;
            }
            synchronized (lock) {
                lock.wait(5000);
            }
            synchronized (mIDMap){
                mIDMap.remove(id);
            }
            return result[0];
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    private String upload(String fileName, byte[] data, OSNTransferCallback callback){
        JSONObject result = new JSONObject();
        result.put("state", "Start");
        result.put("name", fileName);
        JSONObject json = OsnUtils.makeMessage("UploadData",mOsnID,mServiceID,result,null,false);
        json = sendPackage(json, null);
        if(!isSuccess(json)){
            OsnUtils.logInfo(errCode(json));
            if(callback != null) {
                callback.onFailure(errCode(json));
                return null;
            }
            return errCode(json);
        }
        json = OsnUtils.takeMessage(json,mOsnKey);

        int i;
        String key = json.getString("key");
        OsnUtils.logInfo("key: " + key);

        result.clear();
        result.put("state", "Upload");
        result.put("key", key);
        int bLength = 4096;
        byte[] d = new byte[bLength];
        for(i = 0; i < data.length/bLength; ++i){
            System.arraycopy(data, i*bLength, d, 0, bLength);
            result.put("data", Base58.encode(d));
            json = OsnUtils.makeMessage("UploadData",mOsnID,mServiceID,result,null,false);
            sendPackage(json);
        }
        if(data.length%bLength != 0){
            int length = data.length%bLength;
            d = new byte[length];
            System.arraycopy(data,i*bLength,d,0,length);
            result.put("data", Base58.encode(d));
            json = OsnUtils.makeMessage("UploadData",mOsnID,mServiceID,result,null,false);
            sendPackage(json);
        }
        result.put("state", "End");
        result.remove("data");
        json = OsnUtils.makeMessage("UploadData",mOsnID,mServiceID,result,null,false);
        json = sendPackage(json, null);
        if(!isSuccess(json)) {
            if(callback != null) {
                callback.onFailure(errCode(json));
                return null;
            }
            return errCode(json);
        }
        json = OsnUtils.takeMessage(json,mOsnKey);
        if(callback != null) {
            callback.onSuccess(json.toString());
            return null;
        }
        return json.toString();
    }
    private void download(String remoteUrl, String localPath, String target, OSNTransferCallback callback){
        try {
            OsnUtils.logInfo(remoteUrl+localPath+target);
            File file = new File(localPath);
            JSONObject data = new JSONObject();
            data.put("state", "Start");
            data.put("url", remoteUrl);
            JSONObject json = OsnUtils.makeMessage("DownloadData", mOsnID, target, data,null,false);
            json = sendPackage(json, null);
            if (!isSuccess(json)) {
                OsnUtils.logInfo("error: " + errCode(json));
                if(callback != null)
                    callback.onFailure(errCode(json));
                return;
            }

            json = OsnUtils.takeMessage(json,mOsnKey);
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file));

            data.clear();
            data.put("state", "Download");
            data.put("key", json.getString("key"));
            while(true){
                json = OsnUtils.makeMessage("DownloadData", mOsnID, target, data,null,false);
                json = sendPackage(json, null);
                if(!isSuccess(json)){
                    if(callback != null)
                        callback.onFailure(errCode(json));
                    break;
                }
                json = OsnUtils.takeMessage(json,mOsnKey);
                if(json.getString("state").equalsIgnoreCase("End")){
                    bufferedOutputStream.flush();
                    bufferedOutputStream.close();
                    if(callback != null)
                        callback.onSuccess(null);
                    break;
                }
                bufferedOutputStream.write(Base58.decode(json.getString("data")));
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    private boolean isSuccess(JSONObject json){
        return json != null && json.containsKey("errCode") && json.getString("errCode").equalsIgnoreCase("success");
    }
    private String errCode(JSONObject json){
        if(json == null)
            return "null";
        if(!json.containsKey("errCode"))
            return "none";
        return json.getString("errCode");
    }

    private MessageInfo toMessage(JSONObject json){
        try {
            MessageInfo messageInfo = null;
            JSONObject content = OsnUtils.takeMessage(json,mOsnKey);
            if (content != null) {
                messageInfo = new MessageInfo();
                messageInfo.userID = json.getString("from");
                messageInfo.target = json.getString("to");
                messageInfo.timeStamp = json.getLong("timestamp");
                messageInfo.content = content.getString("content");
                messageInfo.isGroup = messageInfo.userID.startsWith("OSNG");
                messageInfo.originalUser = content.getString("originalUser");
            }
            return messageInfo;
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }

    private void syncGroup(){
        try{
            JSONObject json = OsnUtils.makeMessage("GetGroupList",mOsnID,mServiceID,null,mOsnKey,false);
            json = sendPackage(json, null);
            if(!isSuccess(json)){
                OsnUtils.logInfo(errCode(json));
                return;
            }
            JSONObject data = OsnUtils.takeMessage(json,mOsnKey);
            JSONArray groupList = data.getJSONArray("groupList");
            if (groupList == null) {
                OsnUtils.logInfo("groupList == null");
                return;
            }
            for(Object o:groupList){
                GroupInfo groupInfo = new GroupInfo();
                groupInfo.groupID = (String)o;
                mOsnListener.onGroupUpdate("SyncGroup", groupInfo, null);
            }
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private void syncFriend(){
        try {
            JSONObject json = OsnUtils.makeMessage("GetFriendList", mOsnID, mServiceID, null, mOsnKey, false);
            json = sendPackage(json, null);
            if (!isSuccess(json)) {
                OsnUtils.logInfo(errCode(json));
                return;
            }
            JSONObject data = OsnUtils.takeMessage(json, mOsnKey);
            if(data == null){
                OsnUtils.logInfo("data == null");
                return;
            }
            JSONArray friendList = data.getJSONArray("friendList");
            if (friendList == null) {
                OsnUtils.logInfo("friendList == null");
                return;
            }
            List<FriendInfo> friendInfoList = new ArrayList<>();
            for (Object o : friendList) {
                JSONObject friend = (JSONObject) o;
                FriendInfo friendInfo = new FriendInfo();
                friendInfo.userID = friend.getString("userID");
                friendInfo.friendID = friend.getString("friendID");
                friendInfo.state = friend.getIntValue("state");
                friendInfoList.add(friendInfo);
            }
            if (friendInfoList.size() != 0)
                mOsnListener.onFriendUpdate(friendInfoList);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private void syncMessage(long timestamp){
        try {
            JSONObject data = new JSONObject();
            data.put("timestamp", timestamp);
            JSONObject json = OsnUtils.makeMessage("MessageSync", mOsnID, mServiceID, data, mOsnKey, false);
            json = sendPackage(json, null);
            if (!isSuccess(json)) {
                OsnUtils.logInfo(errCode(json));
                return;
            }
            handleMessageSync(json);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private void syncCache(long timestamp){
        try {
            JSONObject data = new JSONObject();
            data.put("timestamp", timestamp);
            JSONObject json = OsnUtils.makeMessage("CacheSync", mOsnID, mServiceID, data, mOsnKey, false);
            json = sendPackage(json, null);
            if (!isSuccess(json)) {
                OsnUtils.logInfo(errCode(json));
                return;
            }
            handleCacheSync(json);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }

    private void handleAddFriend(JSONObject json){
        JSONObject data = OsnUtils.takeMessage(json,mOsnKey);
        FriendRequest friendRequest = new FriendRequest();
        friendRequest.reason = data.getString("reason");
        friendRequest.userID = json.getString("from");
        friendRequest.friendID = json.getString("to");
        friendRequest.timeStamp = json.getLong("timestamp");
        friendRequest.state = 0;
        friendRequest.isReaded = false;
        //mFriendRequest.add(friendRequest);
        mOsnListener.onFriendRequest(friendRequest);
    }
    private void handleAgreeFriend(JSONObject json){
        //OsnUtils.logInfo("agreeFriend: " + json.toString());
        //updateFriend("Add", json.getString("from"));
    }
    private void handleMessageRecv(JSONObject json){
        try {
            MessageInfo messageInfo = toMessage(json);
            if (messageInfo == null)
                return;

            List<MessageInfo> msgList = new ArrayList<>();
            msgList.add(messageInfo);
            mOsnListener.onRecvTextMessage(msgList);

            mMsgSync = messageInfo.timeStamp;
            mSp.edit().putLong("msgSync", mMsgSync).apply();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    private void handleMessageSync(JSONObject json){
        JSONObject data = OsnUtils.takeMessage(json,mOsnKey);
        if(data == null) {
            OsnUtils.logInfo("data == null");
            return;
        }
        List<MessageInfo> msgList = new ArrayList<>();
        JSONArray array = data.getJSONArray("msgList");
        for(Object o:array){
            MessageInfo messageInfo = toMessage((JSONObject)o);
            if(messageInfo != null && messageInfo.target.equalsIgnoreCase(mOsnID)) {
                msgList.add(messageInfo);
                mMsgSync = messageInfo.timeStamp;
            }
        }
        if(!msgList.isEmpty())
            mOsnListener.onRecvTextMessage(msgList);
        mSp.edit().putLong("msgSync", mMsgSync).apply();
    }
    private void handleCacheSync(JSONObject json){
        json = OsnUtils.takeMessage(json,mOsnKey);
        JSONArray array = json.getJSONArray("cacheList");
        for(Object o:array)
            handleMessage((String)o);
        mCacheSync = System.currentTimeMillis();
        mSp.edit().putLong("cacheSync", mCacheSync).apply();
    }
    private void handleGroupUpdate(JSONObject json){
        try {
            JSONObject data = OsnUtils.takeMessage(json,mOsnKey);
            JSONArray array = data.getJSONArray("infoList");
            GroupInfo groupInfo = GroupInfo.toGroupInfo(data);
            mOsnListener.onGroupUpdate(data.getString("state"), groupInfo, array == null ? null : array.toJavaList(String.class));
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private void handleUserUpdate(JSONObject json){
        JSONObject data = OsnUtils.takeMessage(json,mOsnKey);
        if(data == null){
            OsnUtils.logInfo("takeMessage == null");
            return;
        }
        UserInfo userInfo = UserInfo.toUserInfo(data);
        JSONArray array = data.getJSONArray("infoList");
        List<String> keys = new ArrayList<>(array.toJavaList(String.class));
        mOsnListener.onUserUpdate(userInfo, keys);
    }
    private void handleFriendUpdate(JSONObject json){
        JSONObject data = OsnUtils.takeMessage(json,mOsnKey);
        FriendInfo friendInfo = FriendInfo.toFriendInfo(data);
        mOsnListener.onFriendUpdate(Collections.singletonList(friendInfo));
    }

    private void initWorker(){
        if(mSock != null)
            return;

        new Thread(new Runnable() {
            @Override
            public void run() {
                OsnUtils.logInfo("Start worker thread.");
                while(true) {
                    try {
                        mLogined = false;
                        mSock = new Socket();
                        try {
                            mSock.connect(new InetSocketAddress(mHost, 8100), 5000);
                        }
                        catch (SocketTimeoutException e){
                            OsnUtils.logInfo(e.toString());
                        }
                        catch (Exception e){
                            OsnUtils.logInfo(e.toString());
                            Thread.sleep(5000);
                        }
                        if(!mSock.isConnected()){
                            mSock.close();
                            mOsnListener.onConnectFailed("error read");
                            continue;
                        }
                        mOsnListener.onConnectSuccess();

                        try {
                            InputStream inputStream = mSock.getInputStream();
                            byte[] head = new byte[4];
                            while (true) {
                                if (inputStream.read(head) != 4) {
                                    OsnUtils.logInfo("inputStream.read(head) != 4");
                                    break;
                                }
                                int length = ((head[0] & 0xff) << 24) | ((head[1] & 0xff) << 16) | ((head[2] & 0xff) << 8) | (head[3] & 0xff);
                                byte[] data = new byte[length];
                                int read = 0;
                                while (read < length)
                                    read += inputStream.read(data, read, length - read);
                                String msg = new String(data);
                                new Thread(()->{handleMessage(msg);}).start();
                            }
                        }
                        catch (Exception e){
                            e.printStackTrace();
                            mOsnListener.onConnectFailed(e.toString());
                        }
                        mSock.close();
                        mOsnListener.onConnectFailed("error read");
                    } catch (Exception e) {
                        e.printStackTrace();
                        mOsnListener.onConnectFailed(e.toString());
                    }
                }
            }
        }).start();
        new Thread(new Runnable() {
            @Override
            public void run() {
                OsnUtils.logInfo("Start heart thread.");
                JSONObject json = new JSONObject();
                int time = 0;
                while(true) {
                    try {
                        Thread.sleep(5000);
                        if (mSock != null && mSock.isConnected() && mOsnID != null) {
                            if(mLogined) {
                                if(++time == 2) {
                                    time = 0;
                                    json.clear();
                                    json.put("command", "Heart");
                                    json.put("user", mOsnID);
                                    JSONObject result = sendPackage(json,null);
                                    if(!isSuccess(result))
                                        mSock.close();
                                }
                            }
                            else{
                                login(mOsnID,null);
                            }
                        }
                    }
                    catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
        }).start();
    }
    private boolean loginProc(String user, String key, String type, OSNGeneralCallback callback){
        JSONObject json = new JSONObject();
        json.put("command", "Login");
        json.put("type", type);
        json.put("user", user);
        long random = System.currentTimeMillis();
        JSONObject data = new JSONObject();
        data.put("user", user);
        data.put("random", random);
        json.put("data", OsnUtils.aesEncrypt(data.toString().getBytes(), OsnUtils.Sha256(key.getBytes())));
        json = sendPackage(json, null);
        if(!isSuccess(json)) {
            if(callback != null)
                callback.onFailure(errCode(json));
            return false;
        }
        return loginInfo(json, key, random, callback);
    }
    private boolean loginInfo(JSONObject json, String key, long random, OSNGeneralCallback callback){
        try {
            String data = OsnUtils.aesDecrypt(json.getString("data"), key);
            JSONObject result = JSON.parseObject(data);
            if(result.getLong("random") != random + 1){
                OsnUtils.logInfo("verify failed");
                if(callback != null)
                    callback.onFailure("verify failed");
                return false;
            }
            mAesKey = result.getString("aesKey");
            mOsnID = result.getString("osnID");
            mOsnKey = result.getString("osnKey");
            mServiceID = result.getString("serviceID");
            mSp.edit().putString("osnID", mOsnID)
                    .putString("osnKey", mOsnKey)
                    .putString("aesKey", mAesKey)
                    .putString("serviceID", mServiceID)
                    .apply();
            mLogined = true;
            if(callback != null)
                callback.onSuccess(json.toString());

            new Thread(()->{
                syncFriend();
                syncGroup();
                syncCache(mCacheSync);
                syncMessage(mMsgSync);
            }).start();

            return true;
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
            if(callback != null)
                callback.onFailure(e.toString());
        }
        return false;
    }

    private void handleMessage(String msg){
        try{
            JSONObject json = JSON.parseObject(msg);
            String command = json.getString("command");
            OsnUtils.logInfo(command + ": " + json.toString());

            String id = json.getString("id");
            if(id != null){
                SYNCallback callback = null;
                synchronized (mIDMap){
                    callback = mIDMap.get(id);
                }
                if(callback != null) {
                    callback.onCallback(id, json);
                    return;
                }
            }

            switch(command){
                case "AddFriend":
                    handleAddFriend(json);
                    break;
                case "AgreeFriend":
                    handleAgreeFriend(json);
                    break;
                case "Message":
                    handleMessageRecv(json);
                    break;
                case "MessageSync":
                    handleMessageSync(json);
                    break;
                case "CacheSync":
                    handleCacheSync(json);
                    break;
                case "UserUpdate":
                    handleUserUpdate(json);
                    break;
                case "FriendUpdate":
                    handleFriendUpdate(json);
                    break;
                case "GroupUpdate":
                    handleGroupUpdate(json);
                    break;
                default:
                    OsnUtils.logInfo("unknown command: " + command);
                    break;
            }
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    public static OSNManager Instance() {
        if(INST == null)
            INST = new OSNManager();
        return INST;
    }

    public void initSDK (Context context, String ip, OSNListener listener){
        if(mSp != null)
            return;
        mSp = context.getSharedPreferences("osnp.config", Context.MODE_PRIVATE);
        mOsnID = mSp.getString("osnID", null);
        mOsnKey = mSp.getString("osnKey", null);
        mAesKey = mSp.getString("aesKey", null);
        mServiceID = mSp.getString("serviceID", null);
        mMsgSync = mSp.getLong("msgSync", 0);
        mCacheSync = mSp.getLong("cacheSync", 0);
        if(mMsgSync == 0)
            mMsgSync = System.currentTimeMillis();
        if(mCacheSync == 0)
            mCacheSync = System.currentTimeMillis();

        mHost = ip;
        mOsnListener = listener;
        initWorker();
    }
    public void resetHost(String ip){
        try {
            mHost = ip;
            if (mSock != null)
                mSock.close();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    public boolean login (String userID, OSNGeneralCallback callback){
        return loginProc(userID, mAesKey, "osn", callback);
    }
    public boolean login(String userName, String password, OSNGeneralCallback callback){
        return loginProc(userName, Base58.encode(OsnUtils.Sha256(password.getBytes())), "user", callback);
    }
    public void logout (OSNGeneralCallback callback) {
        try {
            mOsnID = null;
            mLogined = false;
            mSp.edit().putString("osnID",null).commit();
            if (mSock != null)
                mSock.close();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    public String getUserID(){
        return mOsnID;
    }
    public UserInfo getUserInfo(String userID){
        if(userID == null)
            return null;
        JSONObject json = OsnUtils.makeMessage("GetUserInfo", mOsnID, userID, null);
        json = sendPackage(json, null);
        if(!isSuccess(json))
            return null;
        json = OsnUtils.takeMessage(json,mOsnKey);
        return UserInfo.toUserInfo(json);
    }
    public GroupInfo getGroupInfo(String groupID){
        if(groupID == null)
            return null;
        JSONObject json = OsnUtils.makeMessage("GetGroupInfo", mOsnID, groupID, null);
        json = sendPackage(json, null);
        if(!isSuccess(json))
            return null;
        json = OsnUtils.takeMessage(json,mOsnKey);
        return GroupInfo.toGroupInfo(json);
    }
    public void modifyUserInfo(List<String> keys, UserInfo userInfo, OSNGeneralCallback callback){
        JSONObject data = new JSONObject();
        for(String k:keys){
            if(k.equalsIgnoreCase("displayName"))
                data.put("displayName", userInfo.displayName);
            else if(k.equalsIgnoreCase("portrait"))
                data.put("portrait", userInfo.portrait);
        }
        JSONObject json = OsnUtils.makeMessage("SetUserInfo",mOsnID,mServiceID,data,mOsnKey,false);
        json = sendPackage(json, null);
        if(!isSuccess(json)){
            callback.onFailure(errCode(json));
            return;
        }
        callback.onSuccess(null);
    }
    public List<FriendInfo> getFriendList(){
        List<FriendInfo> friendInfoList = new ArrayList<>();
        JSONObject json = OsnUtils.makeMessage("GetFriendList", mOsnID, mServiceID, null,mOsnKey,false);
        json = sendPackage(json, null);
        if(!isSuccess(json))
            return friendInfoList;
        json = OsnUtils.takeMessage(json,mOsnKey);
        JSONArray friendList = json.getJSONArray("friendList");
        if(friendList == null || friendList.isEmpty()) {
            OsnUtils.logInfo("friendList == null || friendList.isEmpty()");
            return friendInfoList;
        }
        for (Object o : friendList) {
            JSONObject friend = (JSONObject) o;
            FriendInfo friendInfo = new FriendInfo();
            friendInfo.userID = friend.getString("userID");
            friendInfo.friendID = friend.getString("friendID");
            friendInfo.state = friend.getIntValue("state");
            friendInfoList.add(friendInfo);
        }
        return friendInfoList;
    }
    public void inviteFriend (String userID, String reason, OSNGeneralCallback callback){
        try {
            JSONObject data = new JSONObject();
            data.put("reason", reason);
            JSONObject json = OsnUtils.makeMessage("AddFriend", mOsnID, userID, data,mOsnKey,false);
            json = sendPackage(json, null);
            if(isSuccess(json)){
                if(callback != null)
                    callback.onSuccess(json.toString());
                return;
            }
            if(callback != null)
                callback.onFailure(errCode(json));
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    public void deleteFriend (String userID, OSNGeneralCallback callback){
        try {
            JSONObject data = new JSONObject();
            data.put("friendID", userID);
            JSONObject json = OsnUtils.makeMessage("DelFriend", mOsnID, mServiceID, data,mOsnKey,false);
            json = sendPackage(json, null);
            if(isSuccess(json)){
                if(callback != null)
                    callback.onSuccess(json.toString());
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if(callback != null)
            callback.onFailure("error");
    }
    public void acceptFriend (String userID, OSNGeneralCallback callback){
        try {
            JSONObject json = OsnUtils.makeMessage("AgreeFriend", mOsnID, userID, null,mOsnKey,false);
            json = sendPackage(json, null);
            if(isSuccess(json)){
                if(callback != null)
                    callback.onSuccess(json.toString());
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if(callback != null)
            callback.onFailure("error");
    }
    public void sendTextMessage (String text, String userID, OSNGeneralCallback callback){
        JSONObject content = new JSONObject();
        content.put("content", text);
        if(userID.startsWith("OSNG"))
            content.put("originalUser", mOsnID);
        JSONObject json = OsnUtils.makeMessage("Message", mOsnID, userID,content,mOsnKey,true);
        json = sendPackage(json, null);
        if(isSuccess(json)) {
            if(callback != null)
                callback.onSuccess(json.toString());
            return;
        }
        if(callback != null)
            callback.onFailure(errCode(json));
    }
    public void createGroup (String groupName, List<String> member, String portrait, OSNGeneralCallback callback){
        JSONArray array = new JSONArray();
        array.addAll(member);
        JSONObject data = new JSONObject();
        data.put("name", groupName);
        data.put("portrait", portrait);
        data.put("userList", array);
        JSONObject json = OsnUtils.makeMessage("CreateGroup",mOsnID,mServiceID,data,null,false);
        json = sendPackage(json, null);
        if(!isSuccess(json)) {
            callback.onFailure(errCode(json));
            return;
        }
        data = OsnUtils.takeMessage(json,mOsnKey);
        if(data == null)
            callback.onFailure("takeMessage");
        else
            callback.onSuccess(data.toString());
    }
    public void addMember (String groupID, List<String> members, OSNGeneralCallback callback){
        JSONArray array = new JSONArray();
        array.addAll(members);
        JSONObject data = new JSONObject();
        data.put("state","AddMember");
        data.put("memberList",array);
        JSONObject json = OsnUtils.makeMessage("AddMember",mOsnID,groupID,data,mOsnKey,false);
        json = sendPackage(json,null);
        if(!isSuccess(json)){
            if(callback != null)
                callback.onFailure(errCode(json));
            return;
        }
        if(callback != null)
            callback.onSuccess(null);
    }
    public void delMember (String groupID, List<String> members, OSNGeneralCallback callback){
        JSONArray array = new JSONArray();
        array.addAll(members);
        JSONObject data = new JSONObject();
        data.put("state","DelMember");
        data.put("memberList",array);
        JSONObject json = OsnUtils.makeMessage("DelMember",mOsnID,groupID,data,mOsnKey,false);
        json = sendPackage(json,null);
        if(!isSuccess(json)){
            if(callback != null)
                callback.onFailure(errCode(json));
            return;
        }
        if(callback != null)
            callback.onSuccess(null);
    }
    public void quitGroup (String groupID, OSNGeneralCallback callback){
        JSONObject data = new JSONObject();
        data.put("state","QuitGroup");
        JSONObject json = OsnUtils.makeMessage("QuitGroup",mOsnID,groupID,data,mOsnKey,false);
        json = sendPackage(json,null);
        if(!isSuccess(json)){
            if(callback != null)
                callback.onFailure(errCode(json));
            return;
        }
        if(callback != null)
            callback.onSuccess(null);
    }
    public void dismissGroup (String groupID, OSNGeneralCallback callback){
        JSONObject data = new JSONObject();
        data.put("state","DelGroup");
        JSONObject json = OsnUtils.makeMessage("DelGroup",mOsnID,groupID,data,mOsnKey,false);
        json = sendPackage(json,null);
        if(!isSuccess(json)){
            if(callback != null)
                callback.onFailure(errCode(json));
            return;
        }
        if(callback != null)
            callback.onSuccess(null);
    }
    public void modifyGroupInfo(List<String> keys, GroupInfo groupInfo, OSNGeneralCallback callback){
        JSONObject data = new JSONObject();
        for(String k:keys){
            if(k.equalsIgnoreCase("name"))
                data.put("name", groupInfo.name);
            else if(k.equalsIgnoreCase("portrait"))
                data.put("portrait", groupInfo.portrait);
        }
        JSONObject json = OsnUtils.makeMessage("SetGroupInfo",mOsnID,groupInfo.groupID,data,mOsnKey,false);
        json = sendPackage(json, null);
        if(!isSuccess(json)){
            callback.onFailure(errCode(json));
            return;
        }
        callback.onSuccess(null);
    }

    public String uploadData(String fileName, byte[] data, OSNTransferCallback callback){
        if(callback == null)
            return upload(fileName,data,null);
        new Thread(()->{upload(fileName,data,callback);}).start();
        return null;
    }
    public void downloadData(String remoteUrl, String localPath, String target, OSNTransferCallback callback){
        if(callback == null) {
            download(remoteUrl,localPath,target,null);
            return;
        }
        new Thread(()->{download(remoteUrl,localPath,target,callback);}).start();
    }
}
