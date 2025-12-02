import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.Arrays;

public class AES_GUI extends JFrame {
    // --- S-box and RCON
    static final int[] sbox = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };
    static final int[] RCON = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};
    static final int[] invSbox = buildInvSbox();

    // --- UI components
    JTextField tfPlain = new JTextField(32);
    JTextField tfKey   = new JTextField(32);
    JButton btnEnc = new JButton("Encrypt");
    JButton btnDec = new JButton("Decrypt");
    JCheckBox cbVerbose = new JCheckBox("Verbose (show rounds)");
    JComboBox<String> paddingBox = new JComboBox<>(new String[]{"PKCS#7", "Pad with #"});
    JTextArea taLog = new JTextArea(18,60);
    JTextField tfHexOut = new JTextField(64);
    JTextField tfPlainOut = new JTextField(64);

    public AES_GUI() {
        super("AES-128 GUI - simple lab tool");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        taLog.setEditable(false);
        tfHexOut.setEditable(false);
        tfPlainOut.setEditable(false);

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4,4,4,4);
        c.gridx = 0; c.gridy = 0; c.anchor = GridBagConstraints.WEST;
        top.add(new JLabel("Plaintext:"), c);
        c.gridx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        top.add(tfPlain, c);

        c.gridx = 0; c.gridy = 1; c.fill = GridBagConstraints.NONE;
        top.add(new JLabel("32-hex Key:"), c);
        c.gridx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        top.add(tfKey, c);

        c.gridx = 0; c.gridy = 2;
        top.add(new JLabel("Padding:"), c);
        c.gridx = 1;
        top.add(paddingBox, c);

        c.gridx = 0; c.gridy = 3;
        top.add(cbVerbose, c);

        c.gridx = 1; c.gridy = 3;
        JPanel btns = new JPanel();
        btns.add(btnEnc);
        btns.add(btnDec);
        top.add(btns, c);

        JPanel middle = new JPanel(new BorderLayout());
        middle.setBorder(BorderFactory.createTitledBorder("Logs"));
        middle.add(new JScrollPane(taLog), BorderLayout.CENTER);

        JPanel bottom = new JPanel(new GridLayout(2,1));
        JPanel out1 = new JPanel(new BorderLayout());
        out1.setBorder(BorderFactory.createTitledBorder("Cipher (HEX)"));
        out1.add(tfHexOut, BorderLayout.CENTER);
        JPanel out2 = new JPanel(new BorderLayout());
        out2.setBorder(BorderFactory.createTitledBorder("Plain / Decrypted"));
        out2.add(tfPlainOut, BorderLayout.CENTER);
        bottom.add(out1);
        bottom.add(out2);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(top, BorderLayout.NORTH);
        getContentPane().add(middle, BorderLayout.CENTER);
        getContentPane().add(bottom, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(null);
        setVisible(true);

        // --- actions
        btnEnc.addActionListener(e -> runEncrypt());
        btnDec.addActionListener(e -> runDecrypt());
    }

    // --- Utilities
    static int[] buildInvSbox() {
        int[] inv = new int[256];
        for (int i = 0; i < 256; i++) inv[i] = 0;
        for (int i = 0; i < 256; i++) {
            inv[sbox[i]] = i;
        }
        return inv;
    }

    static byte[] hexToBytes(String hex) throws IllegalArgumentException {
        if (hex.length() % 2 != 0) throw new IllegalArgumentException("Hex length not even");
        byte[] out = new byte[hex.length()/2];
        for (int i = 0; i < hex.length(); i+=2) {
            out[i/2] = (byte) Integer.parseInt(hex.substring(i,i+2), 16);
        }
        return out;
    }

    static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    void log(String s) {
        taLog.append(s + "\n");
        taLog.setCaretPosition(taLog.getDocument().getLength());
    }

    // --- AES core (Encrypt + Decrypt single block)
    static void subBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = (byte) sbox[state[r][c] & 0xFF];
    }
    static void invSubBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = (byte) invSbox[state[r][c] & 0xFF];
    }
    static void shiftRows(byte[][] state) {
        for (int i = 1; i < 4; i++) {
            byte[] row = new byte[4];
            for (int j = 0; j < 4; j++) row[j] = state[i][(j + i) % 4];
            state[i] = row;
        }
    }
    static void invShiftRows(byte[][] state) {
        for (int i = 1; i < 4; i++) {
            byte[] row = new byte[4];
            for (int j = 0; j < 4; j++) row[j] = state[i][(j - i + 4) % 4];
            state[i] = row;
        }
    }

    static int xtimeInt(int x) {
        x &= 0xFF;
        int res = (x << 1) & 0xFF;
        if ((x & 0x80) != 0) res ^= 0x1B;
        return res;
    }
    static int multiplyInt(int a, int b) {
        int aa = a & 0xFF;
        int bb = b & 0xFF;
        int result = 0;
        for (int i = 0; i < 8; i++) {
            if ((bb & 1) != 0) result ^= aa;
            boolean high = (aa & 0x80) != 0;
            aa = (aa << 1) & 0xFF;
            if (high) aa ^= 0x1B;
            bb >>= 1;
        }
        return result & 0xFF;
    }

    static void mixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            int a0 = state[0][c] & 0xFF;
            int a1 = state[1][c] & 0xFF;
            int a2 = state[2][c] & 0xFF;
            int a3 = state[3][c] & 0xFF;
            int r0 = multiplyInt(0x02, a0) ^ multiplyInt(0x03, a1) ^ a2 ^ a3;
            int r1 = a0 ^ multiplyInt(0x02, a1) ^ multiplyInt(0x03, a2) ^ a3;
            int r2 = a0 ^ a1 ^ multiplyInt(0x02, a2) ^ multiplyInt(0x03, a3);
            int r3 = multiplyInt(0x03, a0) ^ a1 ^ a2 ^ multiplyInt(0x02, a3);
            state[0][c] = (byte) r0; state[1][c] = (byte) r1; state[2][c] = (byte) r2; state[3][c] = (byte) r3;
        }
    }

    static void invMixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            int a0 = state[0][c] & 0xFF;
            int a1 = state[1][c] & 0xFF;
            int a2 = state[2][c] & 0xFF;
            int a3 = state[3][c] & 0xFF;
            int r0 = multiplyInt(0x0e, a0) ^ multiplyInt(0x0b, a1) ^ multiplyInt(0x0d, a2) ^ multiplyInt(0x09, a3);
            int r1 = multiplyInt(0x09, a0) ^ multiplyInt(0x0e, a1) ^ multiplyInt(0x0b, a2) ^ multiplyInt(0x0d, a3);
            int r2 = multiplyInt(0x0d, a0) ^ multiplyInt(0x09, a1) ^ multiplyInt(0x0e, a2) ^ multiplyInt(0x0b, a3);
            int r3 = multiplyInt(0x0b, a0) ^ multiplyInt(0x0d, a1) ^ multiplyInt(0x09, a2) ^ multiplyInt(0x0e, a3);
            state[0][c] = (byte) r0; state[1][c] = (byte) r1; state[2][c] = (byte) r2; state[3][c] = (byte) r3;
        }
    }

    static void addRoundKey(byte[][] state, byte[][] key) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] ^= key[r][c];
    }

    static byte[][][] expandKey(byte[] keyBytes) {
        byte[][][] roundKeys = new byte[11][4][4];
        byte[][] temp = new byte[4][4];
        for (int i = 0; i < 16; i++) temp[i%4][i/4] = keyBytes[i];
        roundKeys[0] = temp;
        for (int r = 1; r < 11; r++) {
            byte[][] prev = roundKeys[r-1];
            byte[][] curr = new byte[4][4];
            byte[] last = { prev[0][3], prev[1][3], prev[2][3], prev[3][3] };
            // rotate
            byte t = last[0]; last[0]=last[1]; last[1]=last[2]; last[2]=last[3]; last[3]=t;
            // sub
            for (int i = 0; i < 4; i++) last[i] = (byte) sbox[last[i] & 0xFF];
            last[0] ^= RCON[r];
            for (int i = 0; i < 4; i++) curr[i][0] = (byte) (prev[i][0] ^ last[i]);
            for (int c = 1; c < 4; c++)
                for (int i = 0; i < 4; i++) curr[i][c] = (byte) (prev[i][c] ^ curr[i][c-1]);
            roundKeys[r] = curr;
        }
        return roundKeys;
    }

    static byte[][] blockToState(byte[] block) {
        byte[][] s = new byte[4][4];
        for (int i = 0; i < 16; i++) s[i%4][i/4] = block[i];
        return s;
    }
    static byte[] stateToBlock(byte[][] s) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) out[i] = s[i%4][i/4];
        return out;
    }

    static byte[] encryptBlock(byte[] block, byte[][][] roundKeys, boolean verbose, java.util.function.Consumer<String> logger) {
        byte[][] state = blockToState(block);
        if (verbose) logger.accept(" Encrypting block: " + bytesToHex(block));
        addRoundKey(state, roundKeys[0]);
        for (int r = 1; r <= 9; r++) {
            subBytes(state); shiftRows(state); mixColumns(state); addRoundKey(state, roundKeys[r]);
            if (verbose) logger.accept("  - after round " + r + ": " + bytesToHex(stateToBlock(state)));
        }
        subBytes(state); shiftRows(state); addRoundKey(state, roundKeys[10]);
        if (verbose) logger.accept("  - final: " + bytesToHex(stateToBlock(state)));
        return stateToBlock(state);
    }

    static byte[] decryptBlock(byte[] block, byte[][][] roundKeys, boolean verbose, java.util.function.Consumer<String> logger) {
        byte[][] state = blockToState(block);
        if (verbose) logger.accept(" Decrypting block: " + bytesToHex(block));
        addRoundKey(state, roundKeys[10]);
        invShiftRows(state); invSubBytes(state);
        if (verbose) logger.accept("  - after inv-sub & inv-shift (pre rounds): " + bytesToHex(stateToBlock(state)));
        for (int r = 9; r >= 1; r--) {
            addRoundKey(state, roundKeys[r]);
            invMixColumns(state);
            invShiftRows(state);
            invSubBytes(state);
            if (verbose) logger.accept("  - after round " + r + ": " + bytesToHex(stateToBlock(state)));
        }
        addRoundKey(state, roundKeys[0]);
        if (verbose) logger.accept("  - final: " + bytesToHex(stateToBlock(state)));
        return stateToBlock(state);
    }

    // --- Padding helpers
    static byte[] pkcs7Pad(byte[] data) {
        int pad = 16 - (data.length % 16);
        if (pad == 0) pad = 16;
        byte[] out = Arrays.copyOf(data, data.length + pad);
        for (int i = data.length; i < out.length; i++) out[i] = (byte) pad;
        return out;
    }
    static byte[] stripPkcs7(byte[] data) {
        if (data.length == 0 || data.length % 16 != 0) return null;
        int pad = data[data.length - 1] & 0xFF;
        if (pad < 1 || pad > 16) return null;
        for (int i = data.length - pad; i < data.length; i++)
            if ((data[i] & 0xFF) != pad) return null;
        return Arrays.copyOf(data, data.length - pad);
    }
    static byte[] hashPad(byte[] data) {
        // pad with '#' (0x23) to full block
        int pad = 16 - (data.length % 16);
        if (pad == 0) pad = 0;
        byte[] out = Arrays.copyOf(data, data.length + pad);
        for (int i = data.length; i < out.length; i++) out[i] = (byte) '#';
        return out;
    }
    static byte[] stripHashPad(byte[] data) {
        int i = data.length;
        while (i > 0 && data[i-1] == (byte) '#') i--;
        return Arrays.copyOf(data, i);
    }

    // --- UI operations
    void runEncrypt() {
        taLog.setText("");
        String plain = tfPlain.getText();
        String key = tfKey.getText().trim();
        boolean verbose = cbVerbose.isSelected();
        boolean usePkcs7 = paddingBox.getSelectedItem().toString().equals("PKCS#7");

        if (!key.matches("(?i)[0-9a-f]{32}")) {
            JOptionPane.showMessageDialog(this, "Key must be 32 hex characters (0-9, A-F).", "Invalid Key", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            byte[] keyBytes = hexToBytes(key);
            log("Got plaintext length=" + plain.length() + " and key=" + key);
            log("Expanding key...");
            byte[][][] roundKeys = expandKey(keyBytes);
            log("Key expansion done.");

            byte[] plainBytes = plain.getBytes("UTF-8");
            byte[] padded = usePkcs7 ? pkcs7Pad(plainBytes) : hashPad(plainBytes);

            log("Encrypting " + (padded.length / 16) + " block(s)...");
            byte[] cipher = new byte[padded.length];
            for (int i = 0; i < padded.length; i += 16) {
                byte[] block = Arrays.copyOfRange(padded, i, i+16);
                byte[] enc = encryptBlock(block, roundKeys, verbose, this::log);
                System.arraycopy(enc, 0, cipher, i, 16);
            }

         tfHexOut.setText(bytesToHex(cipher));

// show raw chars like CLI
String raw = new String(cipher);
tfPlainOut.setText(raw);

// optionally also show length in the log, not by overwriting the field
log("Cipher (raw) length = " + cipher.length);
log("Encryption done.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    void runDecrypt() {
        taLog.setText("");
        String hex = tfPlain.getText().trim(); // user puts cipher hex in plaintext field for decrypt
        String key = tfKey.getText().trim();
        boolean verbose = cbVerbose.isSelected();
        boolean usePkcs7 = paddingBox.getSelectedItem().toString().equals("PKCS#7");

        if (!key.matches("(?i)[0-9a-f]{32}")) {
            JOptionPane.showMessageDialog(this, "Key must be 32 hex characters (0-9, A-F).", "Invalid Key", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (!hex.matches("(?i)[0-9a-f]+") || (hex.length() % 32) != 0) {
            JOptionPane.showMessageDialog(this, "Cipher must be hex and a multiple of 32 hex chars (16 bytes per block).", "Invalid Cipher", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            byte[] cipher = hexToBytes(hex);
            byte[] keyBytes = hexToBytes(key);
            log("Got cipher length=" + cipher.length + " bytes and key=" + key);
            log("Expanding key...");
            byte[][][] roundKeys = expandKey(keyBytes);
            log("Key expansion done.");

            byte[] out = new byte[cipher.length];
            for (int i = 0; i < cipher.length; i += 16) {
                byte[] block = Arrays.copyOfRange(cipher, i, i+16);
                byte[] dec = decryptBlock(block, roundKeys, verbose, this::log);
                System.arraycopy(dec, 0, out, i, 16);
            }

            byte[] result;
            if (usePkcs7) result = stripPkcs7(out);
            else result = stripHashPad(out);

            if (result == null) {
                JOptionPane.showMessageDialog(this, "Padding invalid or decryption failed.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            tfHexOut.setText(bytesToHex(out));
            tfPlainOut.setText(new String(result, "UTF-8"));
            log("Decryption done.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new AES_GUI());
    }
}