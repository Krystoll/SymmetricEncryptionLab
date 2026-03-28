package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class SymmetricEncryptionLab {

    // Глобальные переменные для ключа и IV
    private static SecretKey key;
    private static byte[] iv;

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Ввод исходного текста
        System.out.print("Введите текст для шифрования: ");
        String plainText = scanner.nextLine();

        // Выбор алгоритма
        System.out.print("Выберите алгоритм (AES/DES): ");
        String algorithm = scanner.nextLine().toUpperCase();

        // Выбор режима шифрования
        System.out.print("Выберите режим (ECB/CBC): ");
        String mode = scanner.nextLine().toUpperCase();

        // Генерация ключа и IV
        key = generateKey(algorithm);
        iv = generateIV(algorithm);

        // Шифрование
        byte[] cipherBytes = encrypt(plainText, algorithm, mode, key, iv);
        System.out.println("Зашифрованный текст (Base64): " + Base64.getEncoder().encodeToString(cipherBytes));

        // Дешифрование
        String decrypted = decrypt(cipherBytes, algorithm, mode, key, iv);
        System.out.println("Расшифрованный текст: " + decrypted);

        // Демонстрация разных IV
        System.out.println("\n=== Демонстрация разных IV ===");
        byte[] iv2 = generateIV(algorithm);
        byte[] enc1 = encrypt(plainText, algorithm, "CBC", key, iv);
        byte[] enc2 = encrypt(plainText, algorithm, "CBC", key, iv2);
        System.out.println("IV1: " + Base64.getEncoder().encodeToString(enc1));
        System.out.println("IV2: " + Base64.getEncoder().encodeToString(enc2));

        // Демонстрация ECB vs CBC на повторяющихся блоках
        System.out.println("\n=== ECB vs CBC ===");
        String demoText = "AAAAABBBBBCCCCCAAAAABBBBB";
        byte[] ecb = encrypt(demoText, algorithm, "ECB", key, iv);
        byte[] cbc = encrypt(demoText, algorithm, "CBC", key, iv);
        System.out.println("ECB: " + Base64.getEncoder().encodeToString(ecb));
        System.out.println("CBC: " + Base64.getEncoder().encodeToString(cbc));
    }

    // Генерация ключа
    private static SecretKey generateKey(String algorithm) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        if (algorithm.equals("AES")) {
            keyGen.init(128); // 128 бит AES
        } else if (algorithm.equals("DES")) {
            keyGen.init(56); // DES ключ 56 бит
        }
        return keyGen.generateKey();
    }

    // Генерация IV (для CBC)
    private static byte[] generateIV(String algorithm) {
        int size = algorithm.equals("AES") ? 16 : 8; // AES блок 16 байт, DES 8 байт
        byte[] ivBytes = new byte[size];
        new SecureRandom().nextBytes(ivBytes);
        return ivBytes;
    }

    // Шифрование
    private static byte[] encrypt(String plainText, String algorithm, String mode, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher;
        if (mode.equals("ECB")) {
            cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }
        return cipher.doFinal(plainText.getBytes("UTF-8"));
    }

    // Дешифрование
    private static String decrypt(byte[] cipherBytes, String algorithm, String mode, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher;
        if (mode.equals("ECB")) {
            cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes, "UTF-8");
    }
}
