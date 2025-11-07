package de.usd.cstchef.operations.vietjetair;

import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.signature.KeystoreOperation;
import de.usd.cstchef.view.ui.VariableTextArea;

import javax.crypto.Cipher;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@OperationInfos(name = "API - Body Encryptor", category = OperationCategory.VIETJETAIR, description = "Encrypt VJAPI Body traffic")
public class BodyEncryptor extends KeystoreOperation {
    private VariableTextArea publicKeyTextArea;
    private JComboBox<String> typeComboBox;
    protected String algorithm = "RSA";
    protected String publicKeyString;
    private String lastSelection = "PEM";
    public BodyEncryptor() {
        super();
        this.createUIForPEM();
    }

    public static List<byte[]> chunk(byte[] data, int size) {
        List<byte[]> chunks = new ArrayList<>();
        for (int i = 0; i < data.length; i += size) {
            int end = Math.min(data.length, i + size);
            byte[] piece = new byte[end - i];
            System.arraycopy(data, i, piece, 0, piece.length);
            chunks.add(piece);
        }
        return chunks;
    }

    public static String encryptJsonToBase64(String jsonDataStr, String publicKeyPem) throws Exception {
        String cleanPem = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(cleanPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] plaintextBytes = jsonDataStr.getBytes("UTF-8");

        int maxPlaintextBlockSize = 214; // tuỳ theo key 2048-bit + padding
        List<byte[]> chunks = chunk(plaintextBytes, maxPlaintextBlockSize);

        List<byte[]> encryptedParts = new ArrayList<>();
        for (byte[] block : chunks) {
            encryptedParts.add(cipher.doFinal(block));
        }

        int totalLen = encryptedParts.stream().mapToInt(a -> a.length).sum();
        byte[] fullCipher = new byte[totalLen];
        int pos = 0;
        for (byte[] e : encryptedParts) {
            System.arraycopy(e, 0, fullCipher, pos, e.length);
            pos += e.length;
        }

        return Base64.getEncoder().encodeToString(fullCipher);
    }


    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        if(typeComboBox.getSelectedItem().equals("PEM")) {
            this.publicKeyString = this.publicKeyTextArea.getBytes().toString();
        }
        String body = new String(input.getBytes(), StandardCharsets.UTF_8);
        body = body.replaceAll("null", "\"\"");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonObject = mapper.readTree(body);
        String encrypted = encryptJsonToBase64(mapper.writeValueAsString(jsonObject), this.publicKeyString);
        String output = "{\"encrypted\":\"" + encrypted + "\"}";
        return factory.createByteArray(output.getBytes());
    }
    @Override
    public void createUI() {
        this.typeComboBox = new JComboBox<String>();
        this.typeComboBox.addItem("PEM");
        ActionListener comboBoxActionListener = new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                /* The method should only run if the ActionEvent was triggered by the user in the UI (e.getModifiers() == 16).
                 * Not, for example, when loading a recipe (e.getModifiers() == 0)
                 */
                if(e.getModifiers() == 16) {
                    switch((String) typeComboBox.getSelectedItem()) {
                        case "PEM":
                            if(!lastSelection.equals("PEM")) {
                                clearUI();
                                createUIForPEM();
                            }
                            break;
                    }
                    lastSelection = (String) typeComboBox.getSelectedItem();
                    validate();
                    repaint();
                    updateStepPanel();
                }
            }

        };

        typeComboBox.addActionListener(comboBoxActionListener);
        this.addUIElement("Input Type", typeComboBox);
    }

    private void clearUI() {
        Iterator<String> iterator = this.getUIElements().keySet().iterator();

        while(iterator.hasNext()) {
            String key = iterator.next();
            if(!key.equals("Input Type")) {
                iterator.remove();
                this.clearContentBox(2);
            }
        }
        this.validate();
        this.repaint();
    }

    private void createUIForPEM() {
        this.publicKeyTextArea = new VariableTextArea();
        this.addUIElement("Public Key", this.publicKeyTextArea);
    }

    public void updateStepPanel() {
        super.updateStepPanel();
    }

    @Override
    public void load(Map<String, Object> parameters) {
        if(parameters.get("Input Type").equals("PEM")) {
            this.clearUI();
            this.createUIForPEM();
        }
        super.load(parameters);
    }
}