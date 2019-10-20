package kms_cse_java.CseSample;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

public class UploadEnctyptedObjectUsingKMS {
    static Region clientRegion = Region.AP_NORTHEAST_1 ;
    static String kmsCmkId = System.getenv("AWS_KMS_KEY"); // set your key ID

    static String bucketName = "customer-key-encrypt-dev";
    static String keyName = "output.dat";
    static String dataKeyPath = System.getProperty("user.dir") + "/datakey.txt";

    public static void main(String[] args) throws  Exception {
        String origContent = "S3 Encrypted Object Using KMS-Managed Customer Master Key.";
        System.out.println("Original content: " + origContent);
        System.out.println("key = " + kmsCmkId);

        KmsClient kmsClient = KmsClient.builder().region(clientRegion).build();
        S3Client s3Client = S3Client.builder().region(clientRegion).build();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("aws:s3:arn", "arn:aws:s3:::" + bucketName + "/" + keyName);

        // Generate new data key from CMK on KMS.
        GenerateDataKeyResponse dataKey = kmsClient.generateDataKey(
            GenerateDataKeyRequest.builder()
            .keySpec(DataKeySpec.AES_256)
            .keyId(kmsCmkId)
            .encryptionContext(encryptionContext)
            .build()
        );

        // Encrypt an object.
        cipher.init(
            Cipher.ENCRYPT_MODE,
            new SecretKeySpec(dataKey.plaintext().asByteArray(), "AES"),
            new IvParameterSpec(new byte[16])
        );
        byte[] originalEncrypted = cipher.doFinal(origContent.getBytes());
        
        // Erase plain data key.
        SdkBytes ciphertext = dataKey.ciphertextBlob();
        dataKey = null;

        // Upload the encrypted object.
        s3Client.putObject(
            PutObjectRequest.builder().bucket(bucketName).key(keyName).build(),
            RequestBody.fromBytes(originalEncrypted)
        );

        // Save the encrypted data key.
        FileOutputStream fos = new FileOutputStream(dataKeyPath);
        fos.write(ciphertext.asByteArray());
        fos.close();

        // Download the object. The downloaded object is still encrypted.
        byte downloadedEncrypted[] = s3Client.getObject(
            GetObjectRequest.builder().bucket(bucketName).key(keyName).build(),
            ResponseTransformer.toBytes()
        ).asByteArray();

        // Load the encrypted data key.
        SdkBytes encryptedKeyFromFile = SdkBytes.fromInputStream(new FileInputStream(dataKeyPath));
        DecryptResponse dataKeyFromFile = kmsClient.decrypt(
            DecryptRequest.builder()
            .ciphertextBlob(encryptedKeyFromFile)
            .encryptionContext(encryptionContext)
            .build()
        );

        // Decrypt the encrypted object.
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(dataKeyFromFile.plaintext().asByteArray(), "AES"),
            new IvParameterSpec(new byte[16])
        );
        byte decrypted[] = cipher.doFinal(downloadedEncrypted);

        // Erase data key.
        dataKeyFromFile = null;

        // Verify that the original and decrypted contents are the same size.
        System.out.println("Original content length: " + origContent.length());
        System.out.println("Decrypted content length: " + decrypted.length);
        System.out.println("Decrypted content: " + new String(decrypted));
    }
}
