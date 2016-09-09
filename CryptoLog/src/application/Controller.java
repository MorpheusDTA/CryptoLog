package application;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

/**
 * Controllleur de l'interface
 * 
 * @author Donatien TERTRAIS
 *
 */
public class Controller {

	@FXML protected TextField keyAlias;
	@FXML protected Button browse;
	@FXML protected Label infos;
	@FXML protected TextField resourcePath;
	@FXML protected PasswordField storePassword;
	@FXML protected PasswordField keyPassword;
	private final String keyStoreFile = "keys.keystore";
	private static final Level level = Level.WARNING;
	protected Logger logger = Logger.getLogger(this.getClass().getName());
	
	/**
	 * Création ou récupération du fichier de stockage des clés
	 * 
	 * @param fileName Nom du fichier
	 * @param pw Mot de passe du fichier
	 * @return	Fichier de stockage des clés
	 */
	private KeyStore createKeyStore(String fileName, String pw) {
	    File file = new File(fileName);
	 
	    	KeyStore keyStore = null;
			try {
				keyStore = KeyStore.getInstance("JCEKS");
			} catch (KeyStoreException e) {
				logger.log(level, e.toString());
			}
	    	if (file.exists()) {
	    		// .keystore file already exists => load it
	    		try {
					keyStore.load(new FileInputStream(file), pw.toCharArray());
				} catch ( NoSuchAlgorithmException e) {
					// No  algorithm to check the keystore integrity
					logger.log(level, e.toString());
				} catch ( CertificateException e) {
					// KeyStore certificates cannot be loaded
					logger.log(level, e.toString());
				} catch ( IOException e) {
					// Error keystore file password
					passwordError(1);
					logger.log(level, e.toString());
				}
	    	} else {
	    		// .keystore file not created yet => create it
	    		try {
					keyStore.load(null, null);
		    		keyStore.store(new FileOutputStream(fileName), pw.toCharArray());
				} catch ( NoSuchAlgorithmException e) {
					// The algorithm to check the integrity cannot be found
					logger.log(level, e.toString());
				} catch ( CertificateException e) {
					// The certificate cannot be stored
					logger.log(level, e.toString());
				} catch ( IOException e) {
					logger.log(level, e.toString());
				} catch ( KeyStoreException e) {
					// KeyStore not loaded
					logger.log(level, e.toString());
				}
	    	}
	 
	    return keyStore;
	}
	

	/**
	 * Chiffrement et déchiffrement des fichiers
	 * 
	 * @param cipherMode Mode de chiffrement des fichiers
	 * @param secretKey Cé générée
	 * @param inputFile Fichier d'entrée
	 * @param outputFile Fichier de sortie
	 */
	private void doCrypto(int cipherMode, SecretKey secretKey, File inputFile, File outputFile) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(cipherMode, secretKey);
             
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
             
            byte[] outputBytes = cipher.doFinal(inputBytes);
             
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);
             
            inputStream.close();
            outputStream.close();
             
        } catch ( NoSuchPaddingException e) {
			// Transformation unknown
            logger.log(level, e.toString());
        } catch ( NoSuchAlgorithmException e) {
			// Transformation unknown
            logger.log(level, e.toString());
        } catch ( InvalidKeyException e) {
        	// Key inapropriate to initialize cipher
            logger.log(level, e.toString());
        } catch ( BadPaddingException e) {
        	// Wrong padding of cipher
            logger.log(level, e.toString());
        } catch ( IllegalBlockSizeException e) {
        	// Wrong block size of cipher
            logger.log(level, e.toString());
        } catch ( FileNotFoundException e) {
        	// Unknown input or output file
            logger.log(level, e.toString());
        } catch (IOException e) {
			logger.log(level, e.toString());
		}
    }
	
	/**
	 * Demande de chiffrement d'un fichier
	 */
	@FXML public void encrypt() {
		String path = resourcePath.getText();
		
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey secretKey = keyGen.generateKey();
		
			KeyStore keyStore = null;
			keyStore = createKeyStore(keyStoreFile, storePassword.getText());
	 
			// store the secret key
			KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
			PasswordProtection keyPass = new PasswordProtection(keyPassword.getText().toCharArray());
			keyStore.setEntry(keyAlias.getText(), keyStoreEntry, keyPass);
			keyStore.store(new FileOutputStream(keyStoreFile), storePassword.getText().toCharArray());
			
			doCrypto(Cipher.ENCRYPT_MODE, secretKey, new File(path), new File(path + ".encrypted"));
		} catch ( KeyStoreException e) {
			// Keystore not loaded
			logger.log(level, e.toString());
		} catch ( NoSuchAlgorithmException e) {
			// Unknown algorithm for key generation
			logger.log(level, e.toString());
		} catch ( CertificateException e) {
			// Certificates cannot be stored
			logger.log(level, e.toString());
		} catch ( IOException e) {
			logger.log(level, e.toString());
		}			
	}
	
	/**
	 * Demande de chiffrement d'un fichier
	 */
	@FXML public void decrypt() {
		String path = resourcePath.getText();
		int idx = path.lastIndexOf(".");
		String outputPath = path.substring(0, idx);
		
		int idx2 = outputPath.lastIndexOf(".");
		String extension = outputPath.substring(idx2);
		outputPath = outputPath.substring(0, idx2) + ".decrypted" + extension;

		KeyStore keyStore = null;
		try {
			keyStore = createKeyStore(keyStoreFile, storePassword.getText());
		
	    	// retrieve the stored key back
	    	KeyStore.Entry entry = keyStore.getEntry(keyAlias.getText(), new PasswordProtection(keyPassword.getText().toCharArray()));
	    	SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
	    	
	    	doCrypto(Cipher.DECRYPT_MODE, keyFound, new File(path), new File(outputPath));
	    	
		} catch ( NoSuchAlgorithmException e) {
			// Unknown algorithm to recover the entry
			logger.log(level, e.toString());
		} catch ( UnrecoverableEntryException e) {
			// Error on key password
			logger.log(level, e.toString());
			passwordError(2);
		} catch ( KeyStoreException e) {
			// Keystore not loaded
			logger.log(level, e.toString());
		}
	}
	
	/**
	 * Recherche du fichier à chiffrer/déchiffrer
	 */
	@FXML protected void showBrowser() {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open Resource File");
		String filePath = fileChooser.showOpenDialog(browse.getScene().getWindow()).getAbsolutePath();
		resourcePath.setText(filePath);
	}
	
	/**
	 * Il y a une erreur sur un mot de passe
	 * 
	 * @param i Permet de savoir quel mot de passe est incorrect
	 */
	private void passwordError(int i) {
		switch(i) {
		case 1://error on keystore file
			infos.setText("Error on keystore file password");
			break;
		case 2:// error on key password
			infos.setText("Error on key password");
			break;
		default:
			break;
		}
		
	}
}
