package com.ospn.osnsdk.data;

public class MessageInfo {
    public String userID;
    public String target;
    public String content;
    public long timeStamp;
    public String msgType; //text, voice, image, file, video, location, imageText, pText
    public boolean isGroup;
    public String originalUser;
}
