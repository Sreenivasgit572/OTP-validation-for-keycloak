import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

public class OTPAuthenticator implements Authenticator {
    private static Logger logger = Logger.getLogger(OTPAuthenticator.class);

    private static enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }

    private static final String ENCRYPTION_KEY = "E71FDD277741D2FC8A710ADA5DD4E5D6";
    private static final String ENCRYPTION_IV = "0000000000000000";

    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String mobileNumberAttribute = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.CONF_PRP_USR_ATTR_MOBILE);
        if (mobileNumberAttribute == null) {
            Response challenge = context.form()
                    .setError("Phone number could not be determined.")
                    .createForm("sms-validation-error.ftl");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            return;
        }
        String mobileNumber = OTPAuthenticatorUtil.getAttributeValue(context.getUser(), mobileNumberAttribute);
        if (mobileNumber != null && mobileNumber != "") {
            long nrOfDigits = OTPAuthenticatorUtil.getConfigLong(config, OTPAuthenticatorContstants.CONF_PRP_SMS_CODE_LENGTH, 8L);
            long ttl = OTPAuthenticatorUtil.getConfigLong(config, OTPAuthenticatorContstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s


            String code = getSmsCode(nrOfDigits);
            JDBCExecution jdbcExecution = new JDBCExecution();

//            storeSMSCode(context, code, new Date().getTime() + (ttl * 1000)); // s --> ms
            if (sendSmsCode(mobileNumber, code, context.getAuthenticatorConfig(), context, ttl, context.getUser())) {
                if( !jdbcExecution.isOtpNeeded(context.getUser().getUsername())) {
                    jakarta.ws.rs.core.Response challenge = context.form().createForm("sms-validation.ftl");
                    context.challenge(challenge);
                } else {
                    return;
                }
            } else {
                jakarta.ws.rs.core.Response challenge = context.form()
                        .setError("SMS could not be sent.")
                        .createForm("sms-validation-error.ftl");
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                return;
            }
        } else {
            jakarta.ws.rs.core.Response challenge = context.form()
                    .setError("SMS could not be sent.")
                    .createForm("sms-validation-error.ftl");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            return;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        CODE_STATUS status = null;
        try {
            status = validateCode(context);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        jakarta.ws.rs.core.Response challenge = null;
        System.out.println("Status value ---> " + status);
        switch (status) {
            case EXPIRED:
                challenge = context.form()
                        .setError("The code has been expired.")
                        .createForm("sms-validation.ftl");
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
                break;

            case INVALID:
                if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.CONDITIONAL ||
                        context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE) {
                    System.out.println("Calling context.attempted()");
                    context.attempted();
                } else if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
                    challenge = context.form()
                            .setError("The code is invalid")
                            .createForm("sms-validation.ftl");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                } else {
                    logger.error("Undefined execution ...");
                }
                break;

            case VALID:
                context.success();
                UserModel user = context.getUser();
                user.removeAttribute("otp");
                user.removeAttribute("otp_expiry");
                break;

        }
    }

    private void storeSMSCode(AuthenticationFlowContext context, String code, Long expiringAt) {
        UserModel user = context.getUser();
        System.out.println("txn while storeSMSCode -----------> " + code);
        user.setSingleAttribute("otp", code);
        user.setSingleAttribute("otp_expiry", expiringAt.toString());

        context.success();
    }

    private boolean sendSmsCode(String mobileNumber, String code, AuthenticatorConfigModel config, AuthenticationFlowContext context, long ttl, UserModel user) {

        String smsScheme = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.SMS_SCHEME);
        String smsHost = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.SMS_HOST);
        String smsPath = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.SMS_PATH);
        String smsUsername = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.SMS_USERNAME);
        String smsPassword = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.SMS_PASSWORD);
        String smsFrom = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.SMS_FROM);
        String smsToPrefix = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.SMS_TO_PREFIX);
        String smsText = OTPAuthenticatorUtil.getConfigString(config, OTPAuthenticatorContstants.SMS_TEXT);

        System.out.println(mobileNumber + " " + code);

//            URIBuilder builder = new URIBuilder();
//            builder.setScheme(smsScheme).setHost(smsHost).setPath(smsPath)
//                    .setParameter("Username", smsUsername)
//                    .setParameter("Password", smsPassword)
//                    .setParameter("From", smsFrom)
//                    .setParameter("To", smsToPrefix + mobileNumber)
//                    .setParameter("Message", smsText + " " + code);
//            URI uri = builder.build();
//            HttpGet httpget = new HttpGet(uri);
//            System.out.println(httpget.getURI());
//
//            HttpClient httpClient = HttpClients.createDefault();
//            CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpget);
//            System.out.println(response.toString());
//            StatusLine sl = response.getStatusLine();
//            response.close();
//            if (sl.getStatusCode() != 200) {
//                logger.error("SMS code for " + mobileNumber + " could not be sent: " + sl.getStatusCode() + " - " + sl.getReasonPhrase());
//            }
        String statusCode = "";
        String getResponseCode = "";
        String getResponseMessage = "";
        String returnFlag = "";
        HttpURLConnection connection = null;
        try {
            String query = "username=PRPNUSER&password=PRPNU$#R&msg=Dear Employee, Your OTP to login is " + code + " - APCFSS&template_id=1007645738461585673";
            String msg = "Dear Employee, Your OTP to login is " + code + " - APCFSS";
            System.out.println("query =---> " + query);
//            URL url = new URL("https://www.smsstriker.com/API/sms.php");
//            URL url = new URL("http://cdacsms.apcfss.in/services/APCfssSmsGateWayReq/sendTextSms");
//            connection = (HttpURLConnection) url.openConnection();
//            connection.setDoInput(true);
//            connection.setDoOutput(true);
//            connection.setRequestMethod("POST");
//            HttpURLConnection.setFollowRedirects(true);
//            connection.setRequestProperty("Content-length", String.valueOf(query.length()));
//            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
//            System.out.println("connection established");
//            // open up the output stream of the connection
//            DataOutputStream output = new DataOutputStream(connection.getOutputStream());
//            // write out the data
//            output.writeBytes(query);
//            System.out.println("write bytes completed" );
//            DataInputStream input = new DataInputStream(connection.getInputStream());
//            // read in each character until end-of-stream is detected
//            StringBuilder bld = new StringBuilder();
//            System.out.println("************************");
//            for (int c = input.read(); c != -1; c = input.read()) {
//                bld.append((char) c);
//                bld.append("");
//                System.out.print((char) c);
//            }
//            statusCode = bld.toString();
//            System.out.println("************************");
//            System.out.println("response --> " + statusCode);
//            getResponseCode = connection.getResponseCode() + "";
//            getResponseMessage = connection.getResponseMessage();
//            if (getResponseCode.equalsIgnoreCase("200")) {
//                return true;
//            } else {
//                return false;
//            }
            //OtpSendMethod(mobileNumber, code);

            sendAadharOtp(mobileNumber, context, ttl, user);

        } catch (IOException e) {
            logger.error("sendSms called ... SecretQuestionAuthenticator" + e);
            return false;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return true;
    }

    private void sendAadharOtp(String mobileNumber, AuthenticationFlowContext context, long ttl, UserModel user) throws IOException {
        String serviceURL = "https://adharservicess.apcfss.in/cfss/aadharservices/otpGeneration";
        //System.out.println("caste-certificate-url="+serviceURL);

        String userpass = "utilities:swte@m482";
        //String userpass =env.getProperty("master-data-correction-user-pass") ;
        String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes());

        URL obj = new URL(serviceURL);
        HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();

        postConnection.setRequestProperty ("Authorization", basicAuth);
        postConnection.setRequestMethod("POST");
        postConnection.setRequestProperty("Content-Type", "application/json");

        postConnection.setDoOutput(true);
        OutputStream os = postConnection.getOutputStream();

        //Gson gsonObj = new Gson();
        //String jsonStr = gsonObj.toJson(emp);
        JDBCExecution jdbc = new JDBCExecution();
        String aadharNo = jdbc.getAadhaar(user.getUsername());
        String jsonStr="{\"aadharno\":\""+aadharNo+"\",\"unique_key\":\"d35cfd929c5365b7710278838764ac61\"}";
        //System.out.println("Request="+jsonStr.toString());
        os.write(jsonStr.getBytes());
        os.flush();
        os.close();

        int responseCode = postConnection.getResponseCode();
        System.out.println("responseCode="+responseCode);

        if (responseCode == HttpURLConnection.HTTP_OK) { //success	 HTTP Status-Code 200: OK.

            BufferedReader in = new BufferedReader(new InputStreamReader(postConnection.getInputStream()));
            String inputLine;
            StringBuffer br = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                br.append(inputLine);
            }
            in.close();
            // print result

            String output = br.toString();

            System.out.println("Response=" + output);
            Map<String, String> jsonMap = new HashMap<>();
            String[] keyValuePairs = output.replaceAll("[{}\"]", "").split(",");
            for (String pair : keyValuePairs) {
                System.out.println("Map iteration --> ");
                String[] entry = pair.split(":", 2); // Limit the split to 2 elements
                if (entry.length == 2) {
                    System.out.println("Map iteration key --> " + entry[0].trim());
                    System.out.println("Map iteration value --> " + entry[1]);
                    jsonMap.put(entry[0].trim(), (entry[1] == null || entry[1].trim().equalsIgnoreCase("")) ? "" : entry[1].trim());
                } else {
                    System.out.println("Invalid key-value pair: " + pair);
                }
            }

            String txn = jsonMap.get("txn");
            System.out.println("Before storeSMSCode -----------> ");
            storeSMSCode(context, encrypt(aadharNo) + "&&&&" +txn, new Date().getTime() + (ttl * 1000));
            System.out.println("After storeSMSCode -----------> ");
        }
    }

    private String getSmsCode(long nrOfDigits) {
        if (nrOfDigits < 1) {
            throw new RuntimeException("Nr of digits must be bigger than 0");
        }

        double maxValue = Math.pow(10.0, nrOfDigits); // 10 ^ nrOfDigits;
        Random r = new Random();
        long code = (long) (r.nextFloat() * maxValue);
        return Long.toString(code);
    }

    protected CODE_STATUS validateCode(AuthenticationFlowContext context) throws IOException {
        System.out.println("inside validate code");
        CODE_STATUS result = CODE_STATUS.VALID;
        jakarta.ws.rs.core.MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(OTPAuthenticatorContstants.ANSW_SMS_CODE);
        String expectedCode = OTPAuthenticatorUtil.getAttributeValue(context.getUser(), "otp");
        String expTimeString = OTPAuthenticatorUtil.getAttributeValue(context.getUser(), "otp_expiry");
        if (expectedCode != null) {
            // validate Aadhaar otp
           boolean validationOfOtpStatus = validateAadharOtp(expectedCode, enteredCode);
            //result = enteredCode.equals(expectedCode) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            long now = new Date().getTime();

            System.out.println("validationOfOtpStatus --> " + validationOfOtpStatus);
            // modify
            if (validationOfOtpStatus) {
                System.out.println("Inside validationOfOtpStatus true --> comparing expTime --> " + (Long.parseLong(expTimeString) < now));
                if (Long.parseLong(expTimeString) < now) {
                    result = CODE_STATUS.VALID;
                } else {
                    result = CODE_STATUS.EXPIRED;
                }

            } else {
                result = CODE_STATUS.INVALID;
            }
        }
        System.out.println("result of otp validation --> " + result);
        return result;
    }

    public static String decrypt(String src) {
        String decrypted = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, makeKey(), makeIv());
            decrypted = new String(cipher.doFinal(Base64.decodeBase64(src)));
        } catch (Exception e) {
            throw new RuntimeException("Invalid Id");
        }
        return decrypted;
    }
    static AlgorithmParameterSpec makeIv() {
        try {
            return new IvParameterSpec(ENCRYPTION_IV.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    static Key makeKey() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(ENCRYPTION_KEY.getBytes("UTF-8"));
            return new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String encrypt(String src) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, makeKey(), makeIv());
            return Base64.encodeBase64String(cipher.doFinal(src.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private boolean validateAadharOtp(String encryptedAadharNo, String otp) throws IOException {
        System.out.println("Aadhar passing for decrypt --> " + encryptedAadharNo.split("&&&&")[0]);
        String aadharNo = decrypt(encryptedAadharNo.split("&&&&")[0]);
        String trn = encryptedAadharNo.split("&&&&")[1];
//        aadharNo = "218389535821";
        System.out.println("UID="+aadharNo);

        String serviceURL = "https://adharservicess.apcfss.in/cfss/aadharservices/OtpReponse";
        //System.out.println("caste-certificate-url="+serviceURL);

        String userpass = "utilities:swte@m482";
        //String userpass =env.getProperty("master-data-correction-user-pass") ;
        String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes());

        URL obj = new URL(serviceURL);
        HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();

        postConnection.setRequestProperty("Authorization", basicAuth);
        postConnection.setRequestMethod("POST");
        postConnection.setRequestProperty("Content-Type", "application/json");

        postConnection.setDoOutput(true);
        OutputStream os = postConnection.getOutputStream();

        //Gson gsonObj = new Gson();
        //String jsonStr = gsonObj.toJson(emp);

        String jsonStr = "{\"aadharno\":\"" + aadharNo + "\",\"unique_key\": \"d35cfd929c5365b7710278838764ac61\",\"otp\":\"" + otp + "\",\"txnNo\":\"" + trn + "\"}";
        //System.out.println("Request="+jsonStr.toString());
        os.write(jsonStr.getBytes());
        os.flush();
        os.close();

        int responseCode = postConnection.getResponseCode();
        //System.out.println("responseCode="+responseCode);

        if (responseCode == HttpURLConnection.HTTP_OK) { //success	 HTTP Status-Code 200: OK.

            BufferedReader in = new BufferedReader(new InputStreamReader(postConnection.getInputStream()));
            String inputLine;
            StringBuffer br = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                br.append(inputLine);
            }
            in.close();
            // print result

            String output = br.toString();

            System.out.println("Response=" + output);
            System.out.println("Response=" + output);
            Map<String, String> jsonMap = new HashMap<>();
            String[] keyValuePairs = output.replaceAll("[{}\"]", "").split(",");
            for (String pair : keyValuePairs) {
                System.out.println("Map iteration --> ");
                String[] entry = pair.split(":", 2); // Limit the split to 2 elements
                if (entry.length == 2) {
                    System.out.println("Map iteration key --> " + entry[0].trim());
                    System.out.println("Map iteration value --> " + entry[1]);
                    jsonMap.put(entry[0].trim(), (entry[1] == null || entry[1].trim().equalsIgnoreCase("")) ? "" : entry[1].trim());
                } else {
                    System.out.println("Invalid key-value pair: " + pair);
                }
            }

            String ret = jsonMap.get("ret");

            System.out.println("retun value --> ret.equalsIgnoreCase(y) --> " + ret.equalsIgnoreCase("Y"));
            return ret.equalsIgnoreCase("Y");

        }
        return false;
    }


    @Override
    public boolean requiresUser() {
        return true;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }


    public void OtpSendMethod(String mobileNo, String code) throws Exception {
        Map<String,Object>responseMap=new LinkedHashMap<>();
        //String otp=null;
        String NUMERIC_REGEX = "^[0-9]+$";
        OTPForm otpform = null;
        {
            System.out.println("mobileNo:::======================================"+mobileNo);
            otpform = new OTPForm();
            Date date = new Date();
            if(code!=null && code.length() == 5)
                code = "9"+code;

            otpform.setSMSID("P"+date.getTime());
            otpform.setMOBNO(mobileNo);
            System.out.println("otpCode1="+code);
            otpform.setSMSTEXT("Dear Employee, Your OTP to login is "+code+" - APCFSS");

            System.out.println("otpCode2="+code);
            otpform.setPROJCODE("APESR");
            otpform.setTEMPLATEID("1007645738461585673");
            POSTRequest(otpform);
//            int status = POSTRequest(otpform);
//            if(status==1) {
//                responseMap.put("SCODE","01");
//                System.out.println("OTP sent to your registered mobile no. "+" "+"******"+(mobileNo).substring(mobileNo.length()-4));
//
//
//            }
//            else if(status==2) {
//                responseMap.put("SCODE", "02");
//                System.out.println("Mobile Network Error! Please Try Again!");
//            }
//            else if(status==3) {
//                responseMap.put("SCODE", "02");
//                System.out.println("OTP Not Sent. Mobile Network Error!!");
//            }
//            else {
//                responseMap.put("SCODE", "02");
//                System.out.println("OTP Not Sent. Mobile Network Error!!!");
//            }
        }
//        return responseMap;
    }

    /*public static int POSTRequest(OTPForm otpform) throws Exception {

        String SMSID = null, RSPCODE = null, RSPDESC = null;
        int status = 0;

        try

        {
            Gson gsonObj = new Gson();
            String jsonStr = gsonObj.toJson(otpform);

            jsonStr="{\"REQUEST\":"+jsonStr+"}";

            System.out.println("Request="+jsonStr.toString());

            //URL obj = new URL("https://cdacsms.apcfss.in/services/APCfssSmsGateWayReq/sendTextSms");

            URL obj = new URL("http://cdacsms.apcfss.in/services/APCfssSmsGateWayReq/sendTextSms");

            //URL obj = new URL("https://cdacsms.apcfss.in/services/APCfssSmsGateWayReq/sendTextSms");


            HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();


            String userpass = "PRPNUSER:PRPNU$#R";   // Production Credentials

            String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes());


            postConnection.setRequestProperty ("Authorization", basicAuth);

            postConnection.setRequestMethod("POST");

            postConnection.setRequestProperty("Content-Type", "application/json");

            postConnection.setDoOutput(true);

            OutputStream os = postConnection.getOutputStream();

            os.write(jsonStr.getBytes());

            os.flush();

            os.close();

            int responseCode = postConnection.getResponseCode();
            System.out.println("responseCode "+responseCode);

            if (responseCode == HttpURLConnection.HTTP_OK) {
                //success    HTTP Status-Code 200: OK.
                BufferedReader in = new BufferedReader(new InputStreamReader(postConnection.getInputStream()));
                String inputLine;

                StringBuffer response = new StringBuffer();

                while ((inputLine = in .readLine()) != null) {

                    response.append(inputLine);

                } in .close();

                // print result

                String output = response.toString();

                int postion=output.indexOf(": {");

                output=output.substring(postion+1, output.length() - 1);


                JSONObject jObject = new JSONObject(output);

                if(jObject!=null && jObject.has("SMSID") && jObject.has("RSPCODE") && jObject.has("RSPDESC"))

                {
                    // if SCODE 01, SUCCESS
                    // if SCODE 02, FAILURE

                    SMSID = (String) jObject.get("SMSID");

                    RSPCODE = (String) jObject.get("RSPCODE");
                    RSPDESC = (String) jObject.get("RSPDESC");
                    if(RSPCODE.equals("01"))

                    {

                        System.out.println("SUCCESS");

                        status = 1;

                    }

                    else if(RSPCODE.equals("02"))

                    {

                        System.out.println("FAILURE");

                        status = 2;

                    }

                    else if(RSPCODE.equals("03"))

                    {
                        System.out.println("Invalid Data Format");

                        status = 3;
                    }

                    else

                    {
                        System.out.println("Invalid Data Format");
                        status = 3;

                    }



                }



            } else {

                //System.out.println("Invalid Data Format");

                status = 3;

            }

        }

        catch (Exception e) {

            status = 3;

            e.printStackTrace();

        }

        finally

        {



        }

        return status;


    }*/

    public static void POSTRequest(OTPForm otpform) throws Exception {
        String SMSID = null, RSPCODE = null, RSPDESC = null;
        int status = 0;

        try {
            StringBuilder jsonStr = new StringBuilder();
            jsonStr.append("{\"REQUEST\":{");
            jsonStr.append("\"SMSID\":\"").append(otpform.getSMSID()).append("\",");
            jsonStr.append("\"MOBNO\":\"").append(otpform.getMOBNO()).append("\",");
            jsonStr.append("\"SMSTEXT\":\"").append(otpform.getSMSTEXT()).append("\",");
            jsonStr.append("\"PROJCODE\":\"").append(otpform.getPROJCODE()).append("\",");
            jsonStr.append("\"TEMPLATEID\":\"").append(otpform.getTEMPLATEID()).append("\"}}");

            System.out.println("Request=" + jsonStr);

            URL obj = new URL("http://cdacsms.apcfss.in/services/APCfssSmsGateWayReq/sendTextSms");
            HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();
            System.out.println("after openConnection");

            String userpass = "PRPNUSER:PRPNU$#R";
            String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes());
            System.out.println("Basic Auth --> " + basicAuth);
            postConnection.setRequestProperty("Authorization", basicAuth);
            postConnection.setRequestMethod("POST");
            postConnection.setRequestProperty("Content-Type", "application/json");
            postConnection.setDoOutput(true);

            try (OutputStream os = postConnection.getOutputStream()) {
                os.write(jsonStr.toString().getBytes());
                os.flush();
            }
            System.out.println("After writing to out stream");
            int responseCode = postConnection.getResponseCode();
            System.out.println("responseCode " + responseCode);

            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Success
                BufferedReader in = new BufferedReader(new InputStreamReader(postConnection.getInputStream()));
                String inputLine;
                StringBuffer response = new StringBuffer();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                // Process the response
                String output = response.toString();
                int postion = output.indexOf(": {");
                output = output.substring(postion + 1, output.length() - 1);

//                JSONObject jObject = new JSONObject(output);

//                if (jObject != null && jObject.has("SMSID") && jObject.has("RSPCODE") && jObject.has("RSPDESC")) {
//                    SMSID = jObject.getString("SMSID");
//                    RSPCODE = jObject.getString("RSPCODE");
//                    RSPDESC = jObject.getString("RSPDESC");
//
//                    if (RSPCODE.equals("01")) {
//                        System.out.println("SUCCESS");
//                        status = 1;
//                    } else if (RSPCODE.equals("02")) {
//                        System.out.println("FAILURE");
//                        status = 2;
//                    } else if (RSPCODE.equals("03")) {
//                        System.out.println("Invalid Data Format");
//                        status = 3;
//                    } else {
//                        System.out.println("Invalid Data Format");
//                        status = 3;
//                    }
//                }
            } else {
                // Invalid Data Format
                status = 3;
            }
        } catch (Exception e) {
            status = 3;
            e.printStackTrace();
        }

//        return status;
    }

}