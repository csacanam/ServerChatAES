package control;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;


public class HiloServidor extends Thread 
{
	// Socket
	DatagramSocket dSocketHilo;
	// Servicio de paquetes no orientado a conexión
	DatagramPacket dPacketRecibe, dPacketEnvia;
	// Puerto fuente
	int puerto = 0;
	// Dirección fuente
	InetAddress direccion = null;
	
	//SecretKey
	private SecretKey secretKey = null;

	public HiloServidor(DatagramPacket dPacketRecibe) 
	{
		try 
		{
			dSocketHilo = new DatagramSocket();
		} catch (SocketException e) 
		{
			System.out.println("Error creando el socket");
		}

		// Asignar valores a las variables
		this.dPacketRecibe = dPacketRecibe;
		puerto = dPacketRecibe.getPort();
		direccion = dPacketRecibe.getAddress();

		// Respuesta del hilo
		byte[] envio = new byte[250];
		dPacketEnvia = new DatagramPacket(envio, envio.length, direccion, puerto);
		try 
		{
			dSocketHilo.send(dPacketEnvia);
		} catch (IOException e) 
		{
			System.out.println("Error enviando el paquete");
		}
		
		//Asignar clave secreta
		secretKey = diffieHellman();
		
		
		
		
	}

	public void run() 
	{
		while (true) 
		{
			try 
			{
				byte[] buzon = new byte[250];
				dPacketRecibe = new DatagramPacket(buzon, buzon.length);
				dSocketHilo.receive(dPacketRecibe);
				String mensaje = new String(dPacketRecibe.getData(), 0, dPacketRecibe.getLength());
				String mensajeDesencriptado = AES.symmetricDecrypt(mensaje,secretKey);
				System.out.println("El mensaje encriptado es: " + mensaje);
				System.out.println("El mensaje desencriptado es: " + mensajeDesencriptado);
			} catch (IOException e) 
			{
				System.out.println("Error en el flujo");
			} 

		}

	}
	
	/**
	 * Permite generar una clave secreta usando el algoritmo Diffie Hellman
	 * @return
	 */
	public SecretKey diffieHellman()
	{
		SecretKey aesSecretKey = null;
		String algorithm = "DH";
		try 
		{
			System.out.println("Recibiendo clave pública del cliente...");
			byte[] buzon = new byte[512];
			dPacketRecibe = new DatagramPacket(buzon, buzon.length);
			dSocketHilo.receive(dPacketRecibe);
			KeyFactory kf = KeyFactory.getInstance(algorithm);
			X509EncodedKeySpec xkeysp = new X509EncodedKeySpec(buzon);
			
			PublicKey remotePubKey = kf.generatePublic(xkeysp);
			
			//Obtener los parametros Diffie Hellman de la clave pública del cliente
			DHParameterSpec dhps = ((DHPublicKey)remotePubKey).getParams();
			
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
			keyGenerator.initialize(dhps);
			KeyPair keyPair = keyGenerator.generateKeyPair();
			
			//Crear el KeyAgreement
			KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);
			keyAgreement.init(keyPair.getPrivate());
			
			//Enviar al cliente la clave pública
			byte [] pubKeyBuffer = keyPair.getPublic().getEncoded();
			dPacketEnvia = new DatagramPacket(pubKeyBuffer, pubKeyBuffer.length, direccion, puerto);
			dSocketHilo.send(dPacketEnvia);
			System.out.println("Cantidad de bytes enviados: " + pubKeyBuffer.length);
			
			//Crear clave secreta
			keyAgreement.doPhase(remotePubKey, true);
			aesSecretKey = keyAgreement.generateSecret("AES");
			
			//Imprimir la clave secreta
			byte [] theKey = aesSecretKey.getEncoded();
			System.out.println("Clave secreta: " + bytesToHex(theKey));
			
		} catch (NoSuchAlgorithmException e) 
		{
			System.out.println("El algoritmo no existe");
		} catch (IOException e) 
		{
			System.out.println("Error en el flujo");
		} catch (InvalidKeySpecException e) 
		{
			System.out.println("Especificación de clave inválida");
		} catch (InvalidKeyException e) 
		{
			System.out.println("Clave inválida");
		} catch (InvalidAlgorithmParameterException e) 
		{
			System.out.println("Parámetros inválidos");
		}
		
		return aesSecretKey;
	}
	
	/**
	 * Permite pasar de bytes a hexadecimal
	 * 
	 * @param data
	 *            Informacion representada en bytes
	 * @return Representacion en hexadecimal de la informacion en bytes
	 */
    public static String bytesToHex(byte[] data) 
    {
        if (data == null) 
        {
            return null;
        } else 
        {
            int len = data.length;
            String str = "";
            for (int i = 0; i < len; i++) 
            {
                if ((data[i] & 0xFF) < 16)
                    str = str + "0" + java.lang.Integer.toHexString(data[i] & 0xFF);
                else
                    str = str + java.lang.Integer.toHexString(data[i] & 0xFF);
            }
            return str.toUpperCase();
        }
    }
	
}
