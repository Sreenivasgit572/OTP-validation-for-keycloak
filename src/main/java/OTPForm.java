import java.io.Serializable;

public class OTPForm implements Serializable{
    private String SMSID, MOBNO, SMSTEXT, PROJCODE, TEMPLATEID;

    public String getSMSID() {
        return SMSID;
    }

    public void setSMSID(String sMSID) {
        SMSID = sMSID;
    }

    public String getMOBNO() {
        return MOBNO;
    }

    public void setMOBNO(String mOBNO) {
        MOBNO = mOBNO;
    }

    public String getSMSTEXT() {
        return SMSTEXT;
    }

    public void setSMSTEXT(String sMSTEXT) {
        SMSTEXT = sMSTEXT;
    }

    public String getPROJCODE() {
        return PROJCODE;
    }

    public void setPROJCODE(String pROJCODE) {
        PROJCODE = pROJCODE;
    }

    public String getTEMPLATEID() {
        return TEMPLATEID;
    }

    public void setTEMPLATEID(String tEMPLATEID) {
        TEMPLATEID = tEMPLATEID;
    }





}
