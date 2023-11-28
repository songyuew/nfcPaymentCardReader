package com.arriky.nfcPaymentCardReader;

import android.content.Context;
import android.content.Intent;
import android.media.MediaPlayer;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.Settings;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.github.devnied.emvnfccard.utils.TlvUtil;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.arriky.nfcPaymentCardReader.R;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private final String TAG = "MainAct";
    private com.google.android.material.textfield.TextInputEditText etLog;
    private View loadingLayout;
    private NfcAdapter mNfcAdapter;

    private String outputString = ""; // used for the UI output

    Context context;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        etLog = findViewById(R.id.etLog);
        loadingLayout = findViewById(R.id.loading_layout);

        context = getApplicationContext();

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    /**
     * section for NFC
     */

    /**
     * This method is run in another thread when a card is discovered
     * This method cannot direct interact with the UI Thread
     * Use `runOnUiThread` method to change the UI from this method
     *
     * @param tag discovered tag
     */

    @Override
    public void onTagDiscovered(Tag tag) {
        boolean cardRed = false;
        clearData();
        writeToUiAppend("NFC tag discovered");
        playSinglePing();
        setLoadingLayoutVisibility(true);
        byte[] tagId = tag.getId();

        String[] techList = tag.getTechList();
        boolean isoDepInTechList = false;
        for (String s : techList) {
            if (s.equals("android.nfc.tech.IsoDep")) isoDepInTechList = true;
        }
        // proceed only if tag has IsoDep in the techList
        if (isoDepInTechList) {
            IsoDep nfc = null;
            nfc = IsoDep.get(tag);
            if (nfc != null) {
                try {
                    nfc.connect();
                    writeToUiAppend("Connection with card success");

                    /**
                     * step 1 code start
                     */

                    byte[] PPSE = "2PAY.SYS.DDF01".getBytes(StandardCharsets.UTF_8); // PPSE
                    byte[] selectPpseCommand = selectApdu(PPSE);
                    byte[] selectPpseResponse = nfc.transceive(selectPpseCommand);
                    byte[] selectPpseResponseOk = checkResponse(selectPpseResponse);
                    // proceed only when te do have a positive read result = 0x'9000' at the end of response data
                    if (selectPpseResponseOk != null) {

                        BerTlvParser parser = new BerTlvParser();
                        BerTlvs tlv4Fs = parser.parse(selectPpseResponseOk);
                        // find all entries for tag 0x4f
                        List<BerTlv> tag4fList = tlv4Fs.findAll(new BerTag(0x4F));
                        if (tag4fList.size() < 1) {
                            writeToUiAppend("Card reading error");
                            startEndSequence(nfc);
                        }
                        ArrayList<byte[]> aidList = new ArrayList<>();
                        for (int i4f = 0; i4f < tag4fList.size(); i4f++) {
                            BerTlv tlv4f = tag4fList.get(i4f);
                            byte[] tlv4fBytes = tlv4f.getBytesValue();
                            aidList.add(tlv4fBytes);
                        }

                        for (int aidNumber = 0; aidNumber < tag4fList.size(); aidNumber++) {
                            byte[] aidSelected = aidList.get(aidNumber);
                            byte[] selectAidCommand = selectApdu(aidSelected);
                            byte[] selectAidResponse = nfc.transceive(selectAidCommand);

                            byte[] selectAidResponseOk = checkResponse(selectAidResponse);
                            if (selectAidResponseOk != null) {
                                BerTlvs tlvsAid = parser.parse(selectAidResponseOk);
                                BerTlv tag9f38 = tlvsAid.find(new BerTag(0x9F, 0x38));
                                byte[] gpoRequestCommand;


                                if (tag9f38 != null) {
                                    /**
                                     * the following code is for VisaCards and (German) GiroCards as we found a PDOL
                                     */
                                    byte[] pdolValue = tag9f38.getBytesValue();
                                    byte[][] gpoRequestCommandArray = getGpoFromPdolExtended(pdolValue, new byte[]{(byte) 0x00}); // 00 = default, maximum 03
                                    gpoRequestCommand = gpoRequestCommandArray[0];

                                } else { // if (tag9f38 != null) {
                                    /**
                                     * MasterCard code
                                     */
                                    byte[][] gpoRequestCommandArray = getGpoFromPdolExtended(new byte[0], new byte[]{(byte) 0x00});
                                    gpoRequestCommand = gpoRequestCommandArray[0];
                                }

                                byte[] gpoRequestResponse = nfc.transceive(gpoRequestCommand);

                                BerTlvs tlvsGpo = parser.parse(gpoRequestResponse);
                                byte[] aflBytes = null;

                                BerTlv tag57 = tlvsGpo.find(new BerTag(0x57));
                                if (tag57 != null) {
                                    byte[] gpoResponseTag57 = tag57.getBytesValue();
                                    String pan = getPanFromTrack2EquivalentData(gpoResponseTag57);
                                    String expDate = getExpirationDateFromTrack2EquivalentData(gpoResponseTag57);

                                    writeToUiAppend("PAN: " + pan);
                                    String expirationDateString = "Expiration date (" + (expDate.length() == 4 ? "YYMM): " : "YYMMDD): ") + expDate;
                                    cardRed = true;
                                    writeToUiAppend(expirationDateString);

                                }

                                BerTlv tag80 = tlvsGpo.find(new BerTag(0x80));
                                if (tag80 != null) {
                                    byte[] gpoResponseTag80 = tag80.getBytesValue();
                                    aflBytes = Arrays.copyOfRange(gpoResponseTag80, 2, gpoResponseTag80.length);
                                }


                                BerTlv tag77 = tlvsGpo.find(new BerTag(0x77));

                                BerTlv tag94 = tlvsGpo.find(new BerTag(0x94));
                                if (tag94 != null) {
                                    byte[] gpoResponseTag94 = tag94.getBytesValue();
                                    aflBytes = gpoResponseTag94;
                                }


                                List<byte[]> tag94BytesList = divideArray(aflBytes, 4);
                                int tag94BytesListLength = tag94BytesList.size();

                                for (int i = 0; i < tag94BytesListLength; i++) {
                                    byte[] tag94BytesListEntry = tag94BytesList.get(i);
                                    byte sfiOrg = tag94BytesListEntry[0];
                                    byte rec1 = tag94BytesListEntry[1];
                                    byte recL = tag94BytesListEntry[2];
                                    byte offl = tag94BytesListEntry[3]; // offline authorization
                                    int sfiNew = (byte) sfiOrg | 0x04; // add 4 = set bit 3
                                    int numberOfRecordsToRead = (byteToInt(recL) - byteToInt(rec1) + 1);
                                   // read records
                                    byte[] readRecordResponse = new byte[0];
                                    for (int iRecord = (int) rec1; iRecord <= (int) recL; iRecord++) {
                                        byte[] cmd = hexToBytes("00B2000400");
                                        cmd[2] = (byte) (iRecord & 0x0FF);
                                        cmd[3] |= (byte) (sfiNew & 0x0FF);
                                        readRecordResponse = nfc.transceive(cmd);
                                        byte[] readRecordResponseTag5a = null;
                                        byte[] readRecordResponseTag5f24 = null;
                                        if (readRecordResponse != null) {


                                            // checking for PAN and Expiration Date
                                            try {
                                                BerTlvs tlvsReadRecord = parser.parse(readRecordResponse);
                                                BerTlv tag5a = tlvsReadRecord.find(new BerTag(0x5a));
                                                if (tag5a != null) {
                                                    readRecordResponseTag5a = tag5a.getBytesValue();
                                                }
                                                BerTlv tag5f24 = tlvsReadRecord.find(new BerTag(0x5f, 0x24));
                                                if (tag5f24 != null) {
                                                    readRecordResponseTag5f24 = tag5f24.getBytesValue();
                                                }
                                                if (readRecordResponseTag5a != null && cardRed == false) {
                                                    String readRecordPanString = removeTrailingF(bytesToHexNpe(readRecordResponseTag5a));
                                                    String readRecordExpirationDateString = bytesToHexNpe(readRecordResponseTag5f24);
                                                    writeToUiAppend("PAN: " + readRecordPanString);
                                                    String expirationDateString = "Expiration date (" + (readRecordExpirationDateString.length() == 4 ? "YYMM): " : "YYMMDD): ") + readRecordExpirationDateString;
                                                    writeToUiAppend(expirationDateString);
                                                    cardRed = true;
                                                }
                                            } catch (RuntimeException e) {
                                                System.out.println("Runtime Exception: " + e.getMessage());
                                                //startEndSequence(nfc);
                                            }

                                        } else {
                                            writeToUiAppend("Card reading error");
                                        }
                                    }
                                }


                                /**
                                 * step 6 code end
                                 */

                            } else { // if (selectAidResponseOk != null) {
                                writeToUiAppend("Card reading error");
                            }


                        }





                    } else {
                        writeToUiAppend("Card reading error");
                    }

                    vibrate();
                } catch (IOException e) {
                    writeToUiAppend("Connection with card failure");
                    writeToUiAppend(e.getMessage());
                    // throw new RuntimeException(e);
                    startEndSequence(nfc);
                    return;
                }
            }
        } else {
            // if (isoDepInTechList) {
            writeToUiAppend("Card reading error");
        }

        // final cleanup
        playDoublePing();
        writeToUiFinal(etLog);
        setLoadingLayoutVisibility(false);
    }


    /**
     * build a select apdu command
     *
     * @param data
     * @return
     */
    private byte[] selectApdu(@NonNull byte[] data) {
        byte[] commandApdu = new byte[6 + data.length];
        commandApdu[0] = (byte) 0x00;  // CLA
        commandApdu[1] = (byte) 0xA4;  // INS
        commandApdu[2] = (byte) 0x04;  // P1
        commandApdu[3] = (byte) 0x00;  // P2
        commandApdu[4] = (byte) (data.length & 0x0FF);       // Lc
        System.arraycopy(data, 0, commandApdu, 5, data.length);
        commandApdu[commandApdu.length - 1] = (byte) 0x00;  // Le
        return commandApdu;
    }

    /**
     * step 1 code end
     */

    /**
     * step 4 code start
     */

    /**
     * construct the getProcessingOptions command using the provided pdol
     * the default ttq is null, but another ttq can used if default ttq gives no result for later sending
     * @param pdol
     * @param alternativeTtq
     * @return a byte[][] array
     * [0] = getProcessingOptions command
     * [1] = text table with requested tags from pdol with length and value
     */
    private byte[][] getGpoFromPdolExtended(@NonNull byte[] pdol, byte[] alternativeTtq) {

        byte[][] result = new byte[2][];
        // get the tags in a list
        List<com.github.devnied.emvnfccard.iso7816emv.TagAndLength> tagAndLength = TlvUtil.parseTagAndLength(pdol);
        int tagAndLengthSize = tagAndLength.size();
        StringBuilder returnString = new StringBuilder();
        returnString.append("The card is requesting " + tagAndLengthSize + (tagAndLengthSize == 1 ? " tag" : " tags")).append(" in the PDOL").append("\n");
        returnString.append("\n");
        returnString.append("Tag  Tag Name                        Length Value").append("\n");
        returnString.append("-----------------------------------------------------").append("\n");
        if (tagAndLengthSize < 1) {
            returnString.append("     no PDOL provided, returning an empty command").append("\n");
            returnString.append("-----------------------------------------------------");
            // there are no pdols in the list
            //Log.e(TAG, "there are no PDOLs in the pdol array, aborted");
            //return null;
            // returning an empty PDOL
            String tagLength2d = "00"; // length value
            String tagLength2dAnd2 = "02"; // length value + 2
            String constructedGpoCommandString = "80A80000" + tagLength2dAnd2 + "83" + tagLength2d + "" + "00";
            result[0] = hexToBytes(constructedGpoCommandString);
            result[1] = returnString.toString().getBytes(StandardCharsets.UTF_8);
            return result;
            //return hexToBytes(constructedGpoCommandString);
        }
        int valueOfTagSum = 0; // total length
        StringBuilder sb = new StringBuilder(); // takes the default values of the tags
        DolValues dolValues = new DolValues();
        for (int i = 0; i < tagAndLengthSize; i++) {
            // get a single tag
            com.github.devnied.emvnfccard.iso7816emv.TagAndLength tal = tagAndLength.get(i); // eg 9f3704
            byte[] tagToSearch = tal.getTag().getTagBytes(); // gives the tag 9f37
            int lengthOfTag = tal.getLength(); // 4
            String nameOfTag = tal.getTag().getName();
            valueOfTagSum += tal.getLength(); // add it to the sum
            // now we are trying to find a default value
            byte[] defaultValue = dolValues.getDolValue(tagToSearch, alternativeTtq);
            byte[] usedValue = new byte[0];
            if (defaultValue != null) {
                if (defaultValue.length > lengthOfTag) {
                    // cut it to correct length
                    usedValue = Arrays.copyOfRange(defaultValue, 0, lengthOfTag);
                    //Log.i(TAG, "asked for tag: " + bytesToHexNpe(tal.getTag().getTagBytes()) + " default is too long, cut to: " + bytesToHexNpe(usedValue));
                } else if (defaultValue.length < lengthOfTag) {
                    // increase length
                    usedValue = new byte[lengthOfTag];
                    System.arraycopy(defaultValue, 0, usedValue, 0, defaultValue.length);
                    //Log.i(TAG, "asked for tag: " + bytesToHexNpe(tal.getTag().getTagBytes()) + " default is too short, increased to: " + bytesToHexNpe(usedValue));
                } else {
                    // correct length
                    usedValue = defaultValue.clone();
                    //Log.i(TAG, "asked for tag: " + bytesToHexNpe(tal.getTag().getTagBytes()) + " default found: " + bytesToHexNpe(usedValue));
                }
            } else {
                // defaultValue is null means the tag was not found in our tags database for default values
                usedValue = new byte[lengthOfTag];
                //Log.i(TAG, "asked for tag: " + bytesToHexNpe(tal.getTag().getTagBytes()) + " NO default found, generate zeroed: " + bytesToHexNpe(usedValue));
            }
            // now usedValue does have the correct length
            sb.append(bytesToHexNpe(usedValue));
            returnString.append(trimStringRight(bytesToHexNpe(tagToSearch),5)).append(trimStringRight(nameOfTag, 36)).append(trimStringRight(String.valueOf(lengthOfTag), 3)).append(bytesToHexBlankNpe(usedValue)).append("\n");
        }
        returnString.append("-----------------------------------------------------").append("\n");
        String constructedGpoString = sb.toString();
        String tagLength2d = bytesToHexNpe(intToByteArray(valueOfTagSum)); // length value
        String tagLength2dAnd2 = bytesToHexNpe(intToByteArray(valueOfTagSum + 2)); // length value + 2
        String constructedGpoCommandString = "80A80000" + tagLength2dAnd2 + "83" + tagLength2d + constructedGpoString + "00";
        result[0] = hexToBytes(constructedGpoCommandString);
        result[1] = returnString.toString().getBytes(StandardCharsets.UTF_8);
        return result;
    }

    /**
     * step 4 code end
     */

    /**
     * step 7 code start
     */

    private String getPanFromTrack2EquivalentData(byte[] track2Data) {
        if (track2Data != null) {
            String track2DataString = bytesToHexNpe(track2Data);
            int posSeparator = track2DataString.toUpperCase().indexOf("D");
            return removeTrailingF(track2DataString.substring(0, posSeparator));
        } else {
            return "";
        }
    }

    private String getExpirationDateFromTrack2EquivalentData(byte[] track2Data) {
        if (track2Data != null) {
            String track2DataString = bytesToHexNpe(track2Data);
            int posSeparator = track2DataString.toUpperCase().indexOf("D");
            return track2DataString.substring((posSeparator + 1), (posSeparator + 5));
        } else {
            return "";
        }
    }

    /**
     * remove all trailing 0xF's trailing in the 16 byte length field tag 0x5a = PAN and in Track2EquivalentData
     * PAN is padded with 'F' if not of length 16
     *
     * @param input
     * @return
     */
    private String removeTrailingF(String input) {
        int index;
        for (index = input.length() - 1; index >= 0; index--) {
            if (input.charAt(index) != 'f') {
                break;
            }
        }
        return input.substring(0, index + 1);
    }

    /**
     * step 7 code end
     */


    /**
     * add blanks to a string on right side up to a length of len
     * if the data.length >= len one character is deleted to get minimum one blank
     *
     * @param data
     * @param len
     * @return
     */
    private String trimStringRight(String data, int len) {
        if (data.length() >= len) {
            data = data.substring(0, (len - 1));
        }
        while (data.length() < len) {
            data = data + " ";
        }
        return data;
    }

    /**
     * checks if the response has an 0x'9000' at the end means success
     * and the method returns the data without 0x'9000' at the end
     * if any other trailing bytes show up the method returns NULL
     *
     * @param data
     * @return
     */
    private byte[] checkResponse(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 5) {
            return null;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status != 0x9000) {
            return null;
        } else {
            return Arrays.copyOfRange(data, 0, data.length - 2);
        }
    }

    /**
     * section for conversion utils
     */

    /**
     * converts a byte array to a hex encoded string
     * This method is Null Pointer Exception (NPE) safe
     *
     * @param bytes
     * @return hex encoded string
     */
    public static String bytesToHexNpe(byte[] bytes) {
        if (bytes != null) {
            StringBuffer result = new StringBuffer();
            for (byte b : bytes)
                result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            return result.toString();
        } else {
            return "";
        }
    }

    /**
     * converts a byte array to a hex encoded string
     * This method is Null Pointer Exception (NPE) safe
     *
     * @param bytes
     * @return hex encoded string with a blank after each value
     */
    public static String bytesToHexBlankNpe(byte[] bytes) {
        if (bytes == null) return "";
        StringBuffer result = new StringBuffer();
        for (byte b : bytes)
            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1)).append(" ");
        return result.toString();
    }

    /**
     * converts a hex encoded string to a byte array
     *
     * @param str
     * @return
     */
    public static byte[] hexToBytes(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(str.substring(2 * i, 2 * i + 2),
                    16);
        }
        return bytes;
    }

    /**
     * converts a byte to int
     *
     * @param b
     * @return
     */
    public static int byteToInt(byte b) {
        return (int) b & 0xFF;
    }

    public static int intFromByteArray(byte[] bytes) {
        return new BigInteger(bytes).intValue();
    }

    /**
     * converts a byte to its hex string representation
     *
     * @param data
     * @return
     */
    public static String byteToHex(byte data) {
        int hex = data & 0xFF;
        return Integer.toHexString(hex);
    }

    /**
     * converts an integer to a byte array
     *
     * @param value
     * @return
     */
    public static byte[] intToByteArray(int value) {
        return new BigInteger(String.valueOf(value)).toByteArray();
    }

    /**
     * splits a byte array in chunks
     *
     * @param source
     * @param chunksize
     * @return a List<byte[]> with sets of chunksize
     */
    private static List<byte[]> divideArray(byte[] source, int chunksize) {
        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }
        return result;
    }

    /**
     * section for NFC
     */

    private void showWirelessSettings() {
        Toast.makeText(this, "You need to enable NFC", Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        startActivity(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (mNfcAdapter != null) {
            if (!mNfcAdapter.isEnabled())
                showWirelessSettings();
            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);
            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    /**
     * important is the disabling of the ReaderMode when activity is pausing
     */

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    /**
     * section for UI
     */

    /**
     * shows a progress bar as long as the reading lasts
     *
     * @param isVisible
     */

    private void setLoadingLayoutVisibility(boolean isVisible) {
        runOnUiThread(() -> {
            if (isVisible) {
                loadingLayout.setVisibility(View.VISIBLE);
            } else {
                loadingLayout.setVisibility(View.GONE);
            }
        });
    }

    private void setCardData() {
        runOnUiThread(() -> {
            etLog.setText("Personal Account Number (PAN)");
        });
    }


    /**
     * vibrate
     */
    private void vibrate() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(200);
        }
    }

    /**
     * Sound files downloaded from Material Design Sounds
     * https://m2.material.io/design/sound/sound-resources.html
     */
    private void playSinglePing() {
        MediaPlayer mp = MediaPlayer.create(this, R.raw.notification_decorative_02);
        mp.start();
    }

    private void playDoublePing() {
        MediaPlayer mp = MediaPlayer.create(this, R.raw.notification_decorative_01);
        mp.start();
    }

    private void startEndSequence(IsoDep nfc) {
        playDoublePing();
//        writeToUiFinal(etLog);
        setLoadingLayoutVisibility(false);
        vibrate();
        try {
            nfc.close();
        } catch (IOException e) {
            // throw new RuntimeException(e);
        }
        return;
    }

    private void clearData() {
        runOnUiThread(() -> {
            outputString = "";
            etLog.setText("");
        });
    }

    private void writeToUiAppend(String message) {
        //System.out.println(message);
        outputString = outputString + message + "\n";
    }

    private void writeToUiFinal(final TextView textView) {
        if (textView == (TextView) etLog) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    textView.setText(outputString);
                    System.out.println(outputString); // print the data to console
                }
            });
        }
    }


}