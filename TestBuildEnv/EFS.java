import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
    External References:
        crypto.stackexchange.com
        stackoverflow.com
        wikipedia.org
 */


public class EFS extends Utility {

    public EFS(Editor e) {
        super(e);
        set_username_password();
    }

    public File folder_name;


    // Method to convert any given string to 128 bytes
    public byte[] stringConverter(String s, byte[] s_bytes, String sname) {
        if (s.length() > 128) {
            for (int i = 0; i < s.substring(0, 128).length(); i++) {
                if (i <= 128)
                    s_bytes[i] = s.substring(0, 128).getBytes(StandardCharsets.UTF_8)[i];
            }
        } else {
            for (int i = 0; i < s.length(); i++) {
                if (i <= 128)
                    s_bytes[i] = s.getBytes(StandardCharsets.UTF_8)[i];
            }
        }
        return s_bytes;
    }


    public byte[] get_BlockData(String file_name, int block) throws Exception {
        File file = new File(file_name);
        File metaData = new File(file, Integer.toString(block));
        return read_from_file(metaData);
    }


    public byte[] get_IV(byte[] block) {
        byte[] temp = new byte[172];
        System.arraycopy(block, 128, temp, 0, 172);
        byte[] iv = Base64.getDecoder().decode(temp);
        return iv;
    }


    public byte[] get_password(byte[] block) {
        byte[] salt = new byte[172];
        System.arraycopy(block, 300, salt, 0, 172);
        byte[] pass = Base64.getDecoder().decode(salt);
        return pass;
    }


    public int get_blockLength(byte[] block, byte[] iv, byte[] pass) throws Exception {

        byte[] temp = new byte[172];
        System.arraycopy(block, 644, temp, 0, 172);

        byte[] encrypted_len = Base64.getDecoder().decode(temp);

        byte[] decrypted_len = new byte[128];
        aes_decryptBuff(pass, iv, encrypted_len, decrypted_len);

        String len = new String(decrypted_len, StandardCharsets.UTF_8).replace("\u0000", "");
        return Integer.parseInt(len);
    }


    public byte[] get_passwordHash(String pass, byte[] iv) throws Exception {

        byte[] tempPass = new byte[128];
        tempPass = stringConverter(pass, tempPass, "password");

        byte[] salt = new byte[tempPass.length + iv.length];
        System.arraycopy(tempPass, 0, salt, 0, tempPass.length);
        System.arraycopy(iv, 0, salt, tempPass.length, iv.length);

        byte[] hash_bits = hash_SHA256(salt);

        byte[] hash_bytes = new byte[128];
        System.arraycopy(hash_bits, 0, hash_bytes, 0, hash_bits.length);

        return hash_bytes;
    }


    private byte[] get_HMAC(byte[] pass, byte[] iv, String text) throws Exception {
        byte[] temp_key = new byte[pass.length + iv.length];
        System.arraycopy(pass, 0, temp_key, 0, pass.length);
        System.arraycopy(iv, 0, temp_key, pass.length, iv.length);
        byte[] k_256bit = hash_SHA256(temp_key);
        byte[] opad = new byte[32];
        byte[] ipad = new byte[32];

        for (int i = 0; i < (256 / 8); i++) {
            opad[i] = (byte) (0x5c ^ k_256bit[i]);
            ipad[i] = (byte) (0x36 ^ k_256bit[i]);
        }
        byte[] text_bytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] textIn = new byte[ipad.length + text_bytes.length];
        System.arraycopy(ipad, 0, textIn, 0, ipad.length);
        System.arraycopy(text_bytes, 0, textIn, ipad.length, text_bytes.length);
        byte[] hash_textIn = hash_SHA256(textIn);

        byte[] textOut = new byte[opad.length + hash_textIn.length];
        System.arraycopy(opad, 0, textOut, 0, opad.length);
        System.arraycopy(hash_textIn, 0, textOut, opad.length, hash_textIn.length);
        byte[] HMAC = hash_SHA256(textOut);
        return HMAC;
    }

    // Method to build 1024 byte blocks for encryption
    public void encryptedBlocks(String file_name, int block, byte[] iv, byte[] pass) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, Integer.toString(block));
        if (!meta.exists()) {
            byte[] newBlock = new byte[1024];
            for (int i = 0; i < 1024; i += 128) {
                byte[] src = new byte[128];
                byte[] dst = new byte[128];
                System.arraycopy(newBlock, i, src, 0, 128);
                aes_encryptBuff(pass, iv, src, dst);
                System.arraycopy(dst, 0, newBlock, i, 128);
            }
            String blockData = Base64.getEncoder().encodeToString(newBlock);
            blockData = blockData.substring(0, 1024);
            save_to_file(blockData.getBytes(StandardCharsets.UTF_8), meta);
        }
    }


    public void aes_encryptBuff(byte[] pass, byte[] iv, byte[] src, byte[] dst) throws Exception {
        int count = 0;
        for (int i = 0; i < src.length; i += 16) {
            byte[] plaintext = new byte[16];
            byte[] key = new byte[16];
            System.arraycopy(src, i, plaintext, 0, 16);
            System.arraycopy(pass, i, key, 0, 8);
            System.arraycopy(iv, i, key, 8, 7);
            key[15] = (byte) (iv[i + 8] + count);
            System.arraycopy(encript_AES(plaintext, key), 0, dst, i, encript_AES(plaintext, key).length);
            count++;
        }
    }


    public void aes_decryptBuff(byte[] pass, byte[] iv, byte[] src, byte[] dst) throws Exception {
        int count = 0;
        for (int i = 0; i < src.length; i += 16) {
            byte[] ciphertext = new byte[16];
            byte[] key = new byte[16];
            System.arraycopy(src, i, ciphertext, 0, 16);
            System.arraycopy(pass, i, key, 0, 8);
            System.arraycopy(iv, i, key, 8, 7);
            key[15] = (byte) (iv[i + 8] + count);
            System.arraycopy(decript_AES(ciphertext, key), 0, dst, i, decript_AES(ciphertext, key).length);
            count++;
        }
    }


    public byte[] aes_HMAC(byte[] pass, byte[] iv, String text) throws Exception {
        byte[] HMAC = get_HMAC(pass, iv, text);
        byte[] HMAC_bytes = new byte[128];
        System.arraycopy(HMAC, 0, HMAC_bytes, 0, HMAC.length);
        byte[] aes_MAC = new byte[128];
        aes_encryptBuff(pass, iv, HMAC_bytes, aes_MAC);
        return aes_MAC;
    }


    public boolean checkPass(String file_name, String pass) throws Exception {
        byte[] block0 = get_BlockData(file_name, 0);
        byte[] iv = get_IV(block0);
        byte[] blockPass = get_password(block0);
        byte[] hashedPass = get_passwordHash(pass, iv);
        return Arrays.equals(hashedPass, blockPass);
    }


    public void writeBlock(String file_name, String text, byte[] iv, byte[] pass, int start) throws Exception {
        String length = Integer.toString(text.length());
        byte[] temp = new byte[128];
        temp = stringConverter(length, temp, "length");
        byte[] lenAES = new byte[128];
        aes_encryptBuff(pass, iv, temp, lenAES);
        byte[] block0 = get_BlockData(file_name, 0).clone();
        System.arraycopy(Base64.getEncoder().encode(lenAES), 0, block0, 644, 172);
        File file = new File(file_name);
        File meta0 = new File(file, Integer.toString(0));
        save_to_file(block0, meta0);
        int blockCount = (text.length() / 128) + 1;
        for (int i = 1; i <= blockCount; i++) {
            encryptedBlocks(file_name, i, iv, pass);
        }
        for (int j = start / 128; j < blockCount; j++) {
            String temp1 = "";
            if ((j * 128) + 128 < text.length()) {
                temp1 = text.substring(j * 128, (j * 128) + 128);
            } else {
                temp1 = text.substring(j * 128);
            }
            byte[] buff = new byte[128];
            buff = stringConverter(temp1, buff, "text");
            byte[] aes_buff = new byte[128];
            aes_encryptBuff(pass, iv, buff, aes_buff);
            byte[] currText = get_BlockData(file_name, j + 1);
            System.arraycopy(Base64.getEncoder().encode(aes_buff), 0, currText, 0, Base64.getEncoder().encode(aes_buff).length);
            File meta1 = new File(file, Integer.toString(j + 1));
            save_to_file(currText, meta1);
            byte[] block1 = get_BlockData(file_name, j).clone();
            byte[] aes_hmac = aes_HMAC(pass, iv, temp1);
            System.arraycopy(Base64.getEncoder().encode(aes_hmac), 0, block1, 472, 172);
            File meta = new File(file, Integer.toString(j));
            save_to_file(block1, meta);
        }
    }

    /**
     * Steps to consider... <p>
     * - add padded username and password salt to header <p>
     * - add password hash and file length to secret data <p>
     * - AES encrypt padded secret data <p>
     * - add header and encrypted secret data to metadata <p>
     * - compute HMAC for integrity check of metadata <p>
     * - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        String meta = "";

        byte[] user_bytes = new byte[128];
        user_bytes = stringConverter(user_name, user_bytes, "username");
        meta += new String(user_bytes, StandardCharsets.UTF_8);

        byte[] iv = secureRandomNumber(128);
        meta += Base64.getEncoder().encodeToString(iv);

        byte[] pass_bytes = new byte[128];
        pass_bytes = stringConverter(password, pass_bytes, "password");

        byte[] pass_salt = new byte[pass_bytes.length + iv.length];
        System.arraycopy(pass_bytes, 0, pass_salt, 0, pass_bytes.length);
        System.arraycopy(iv, 0, pass_salt, pass_bytes.length, iv.length);

        byte[] hash = hash_SHA256(pass_salt);
        byte[] hash_bytes = new byte[128];
        System.arraycopy(hash, 0, hash_bytes, 0, hash.length);
        meta += Base64.getEncoder().encodeToString(hash_bytes);

        String message = "";
        byte[] AES_MAC_128by = aes_HMAC(pass_bytes, iv, message);
        meta += Base64.getEncoder().encodeToString(AES_MAC_128by);
        String length = Integer.toString(message.length());

        byte[] length_128by = new byte[128];
        length_128by = stringConverter(length, length_128by, "length");

        byte[] AES_length_128by = new byte[128];
        aes_encryptBuff(pass_bytes, iv, length_128by, AES_length_128by);
        meta += Base64.getEncoder().encodeToString(AES_length_128by);

        while (meta.length() + 2 < Config.BLOCK_SIZE) {
            int rand_iv = Math.abs(secureRandomNumber(1)[0]) % 128;
            meta += iv[rand_iv];
        }

        folder_name = new File(file_name);
        folder_name.mkdirs();
        File meta1 = new File(folder_name, "0");
        save_to_file(meta.getBytes(StandardCharsets.UTF_8), meta1);
    }


    /**
     * Steps to consider... <p>
     * - check if metadata file size is valid <p>
     * - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {

        byte[] block0 = get_BlockData(file_name, 0);
        byte[] userBlock = new byte[128];
        System.arraycopy(block0, 0, userBlock, 0, 128);

        String user = byteArray2String(userBlock);
        return user;
    }

    /**
     * Steps to consider...:<p>
     * - get password, salt then AES key <p>
     * - decrypt password hash out of encrypted secret data <p>
     * - check the equality of the two password hash values <p>
     * - decrypt file length out of encrypted secret data
     */
    @Override
    public int length(String file_name, String password) throws Exception {

        byte[] block0 = get_BlockData(file_name, 0);
        byte[] IV_ctr_128by = get_IV(block0);
        byte[] password_128by = get_password(block0);
        if (checkPass(file_name, password)) {
            return get_blockLength(block0, IV_ctr_128by, password_128by);
        } else {
            throw new PasswordIncorrectException();
        }
    }

    /**
     * Steps to consider...:<p>
     * - verify password <p>
     * - check check if requested starting position and length are valid <p>
     * - decrypt content data of requested length
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {

        byte[] block0 = get_BlockData(file_name, 0);
        byte[] iv = get_IV(block0);
        byte[] pass = get_password(block0);

        if (!check_integrity(file_name, password)) {
            javax.swing.JOptionPane.showMessageDialog(null, "File modified!!");
        } else {

            if (checkPass(file_name, password)) {
                int l = get_blockLength(block0, iv, pass);
                int blockCount = (l / 128) + 1;
                String pt = "";
                StringBuilder temp = new StringBuilder();

                for (int i = 1; i <= blockCount; i++) {
                    byte[] block1 = get_BlockData(file_name, i);
                    byte[] ct = new byte[172];
                    System.arraycopy(block1, 0, ct, 0, 172);

                    byte[] ct_bytes = Base64.getDecoder().decode(ct);
                    byte[] buffer = new byte[128];

                    aes_decryptBuff(pass, iv, ct_bytes, buffer);
                    temp.append(new String(buffer, StandardCharsets.UTF_8).replace("\u0000", ""));
                }
                pt = temp.substring(starting_position, starting_position + len);
                return pt.getBytes(StandardCharsets.UTF_8);
            } else {
                throw new PasswordIncorrectException();
            }
        }
        return "".getBytes(StandardCharsets.UTF_8);
    }


    /**
     * Steps to consider...:<p>
     * - verify password <p>
     * - check check if requested starting position and length are valid <p>
     * - ### main procedure for update the encrypted content ### <p>
     * - compute new HMAC and update metadata
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {

        byte[] block0 = get_BlockData(file_name, 0);
        byte[] iv = get_IV(block0);
        byte[] pass = get_password(block0);

        if (checkPass(file_name, password)) {
            String pt_write;
            int len;
            try {
                len = length(file_name, password);
            } catch (Exception e) {
                len = 0;
            }
            String pt = new String(content, StandardCharsets.UTF_8);

            if (len > 0) {
                byte[] pt_file = read(file_name, 0, length(file_name, password), password);
                String message_f_str = new String(pt_file, StandardCharsets.UTF_8);
                if (pt.length() >= message_f_str.substring(starting_position, message_f_str.length()).length()) {
                    pt_write = message_f_str.substring(0, starting_position) + pt;
                } else {
                    pt_write = message_f_str.substring(0, starting_position) + pt + message_f_str.substring(starting_position + pt.length(), message_f_str.length());
                }
            } else {
                pt_write = pt;
            }

            writeBlock(file_name, pt_write, iv, pass, starting_position);

        } else {
            throw new PasswordIncorrectException();
        }
    }


    /**
     * Steps to consider...:<p>
     * - verify password <p>
     * - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        byte[] block0 = get_BlockData(file_name, 0);
        byte[] iv = get_IV(block0);
        byte[] pass = get_password(block0);
        if (checkPass(file_name, password)) {
            int len = length(file_name, password);
            int blockCount = (len / 128) + 1;

            for (int i = 0; i < blockCount; i++) {

                byte[] block = get_BlockData(file_name, i);

                byte[] hmac = new byte[172];
                System.arraycopy(block, 472, hmac, 0, 172);

                byte[] hmac_decoded = Base64.getDecoder().decode(hmac);
                byte[] hmac_decrypted = new byte[128];
                aes_decryptBuff(pass, iv, hmac_decoded, hmac_decrypted);

                byte[] mac_file = new byte[32];
                System.arraycopy(hmac_decrypted, 0, mac_file, 0, 32);

                byte[] block1 = get_BlockData(file_name, i + 1);

                byte[] ct = new byte[172];
                System.arraycopy(block1, 0, ct, 0, 172);

                byte[] ct_decoded = Base64.getDecoder().decode(ct);

                byte[] pt = new byte[128];
                aes_decryptBuff(pass, iv, ct_decoded, pt);

                String temp = new String(pt, StandardCharsets.US_ASCII).replace("\u0000", "");

                byte[] mac_pt = get_HMAC(pass, iv, temp);

                if (!Arrays.equals(mac_pt, mac_file)) {
                    return false;
                }

            }
            return true;
        } else {
            throw new PasswordIncorrectException();
        }
    }


    /**
     * Steps to consider... <p>
     * - verify password <p>
     * - truncate the content after the specified length <p>
     * - re-pad, update metadata and HMA C <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {

        byte[] block0 = get_BlockData(file_name, 0);
        byte[] iv = get_IV(block0);
        byte[] pass = get_password(block0);

        int len = length(file_name, password);
        byte[] message_b = read(file_name, 0, len, password);

        String pt = new String(message_b, StandardCharsets.UTF_8);
        String temp = pt.substring(0, length);
        writeBlock(file_name, temp, iv, pass, 0);
    }

}