
package net.asdf.ext.transfer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.ChannelSftp.LsEntry;
import com.jcraft.jsch.ChannelSftp.LsEntrySelector;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.KeyPair;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;
import com.jcraft.jsch.SftpProgressMonitor;
import com.jcraft.jsch.UserInfo;

@Component
public class Sftp {

	private Logger logger = LogManager.getLogger();

	private String 클라이언트아이디;

	private Path sshConfigPath;
	private Path privateKeyPath;
	private Path publicKeyPath;
	private Path knownHostsPath;
	private JSch ssh;

	public Sftp(Class<?> clazz, String 클라이언트아이디) {
		this.클라이언트아이디 = 클라이언트아이디;
		try {
			this.sshConfigPath = Paths.get(clazz.getResource("/").toURI()).resolve("ssh");
			logger.info("config path : {}", this.sshConfigPath.toString());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
	}

	public Sftp(String configPath, String 클라이언트아이디) {
		this.클라이언트아이디 = 클라이언트아이디;
		this.sshConfigPath = FileSystems.getDefault().getPath(configPath);
		logger.info("config path : {}", this.sshConfigPath.toString());
	}

	@PostConstruct
	public void init() {
		getSshConfigPath();
		privateKeyPath = sshConfigPath.resolve(this.클라이언트아이디 + ".key");
		publicKeyPath = sshConfigPath.resolve(this.클라이언트아이디 + ".pub");
		knownHostsPath = sshConfigPath.resolve("known_hosts");

		JSch.setLogger(new JschLogger(logger));
		JSch.setConfig("PreferredAuthentications", "publickey,password");
		JSch.setConfig("StrictHostKeyChecking", "true");
		//JSch.setConfig("compression_level", "0");

		ssh = new JSch();
		try {
			ssh.setKnownHosts(knownHostsPath.toString());
		} catch (JSchException e) {
			e.printStackTrace();
		}

		if(hasKeyPair()) {
			try {
				ssh.addIdentity(privateKeyPath.toString(), publicKeyPath.toString(), null);
			} catch (JSchException e) {
				e.printStackTrace();
			}
		}

	}



	/**
	 * 인증정보 갱신
	 * @return
	 */
	public boolean updateIdentity() {
		if(hasKeyPair()) {
			try {
				ssh.removeAllIdentity();
				ssh.addIdentity(privateKeyPath.toString(), publicKeyPath.toString(), null);
				return true;
			} catch (JSchException e) {
				e.printStackTrace();
			}
		}
		return false;
	}


	/**
	 * 알려진 호스트 등록
	 * @param host
	 * @param port
	 * @return
	 */
	public boolean registerHost(String host, int port) {
		boolean success = false;

		Session session = null;
		ChannelSftp sftp = null;

		try {
			session = ssh.getSession("dummy", host, port);
			session.setConfig("PreferredAuthentications", "password");
			session.setConfig("StrictHostKeyChecking", "ask");
			session.setUserInfo(new AsdfUserInfo("dummy"));

			session.connect(5 * 1000);

			sftp = (ChannelSftp) session.openChannel("sftp");
			sftp.connect(5 * 1000);

			success = true;
		} catch (JSchException e) {
			e.printStackTrace();
		} finally {
			if(sftp != null && sftp.isConnected()) {
				sftp.quit();
			}
			if(session != null && session.isConnected()) {
				session.disconnect();
			}
		}

		return success;
	}

	/**
	 * 접속 확인
	 * @param host
	 * @param port
	 * @param username
	 * @param password 입력하지 않을 경우 공개키기반 인증을 사용한다.
	 * @return
	 */
	public boolean testConnection(String host, int port, String username, String password) {
		boolean success = false;

		Session session = null;
		ChannelSftp sftp = null;

		try {
			session = ssh.getSession(username, host, port);
			if(password != null) {
				session.setConfig("PreferredAuthentications", "password");
				session.setUserInfo(new AsdfUserInfo(password));
			}else {
				session.setConfig("PreferredAuthentications", "publickey");
			}

			session.connect(5 * 1000);

			sftp = (ChannelSftp) session.openChannel("sftp");
			sftp.connect(5 * 1000);

			success = true;
		} catch (JSchException e) {
			e.printStackTrace();
		} finally {
			if(sftp != null && sftp.isConnected()) {
				sftp.quit();
			}
			if(session != null && session.isConnected()) {
				session.disconnect();
			}
		}

		return success;
	}

	public Path getSshConfigPath() {
		Path path = sshConfigPath;
		try {
			path = Paths.get(Sftp.class.getResource("/").toURI());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		logger.info("class root : {}", path.toString());
		path = path.resolve("ssh");
		if(sshConfigPath == null) {
			sshConfigPath = path.toAbsolutePath();
			logger.info("set default config path : {}", path.toString());
		}

		if(sshConfigPath == null) {
			throw new net.asdf.ext.transfer.sftp.SftpException("SSH 설정 경로가 누락 되었습니다.");
		}

		return sshConfigPath;
	}


	/**
	 * 인증키 쌍 생성여부 확인
	 * @return
	 */
	public boolean hasKeyPair() {
		return Files.exists(privateKeyPath) && Files.exists(publicKeyPath);
	}


	/**
	 * 지정 호스트의 알려진 호스트 등록 여부
	 * @param host
	 * @param port
	 * @return
	 */
	public boolean isKnownHost(String host, Integer port) {
		return 0 != ssh.getHostKeyRepository().getHostKey("["+host+"]:" + port, "ssh-rsa").length;
	}

	/**
	 * 인증키 쌍 생성 및 갱신
	 * @return
	 */
	public boolean generateKeyPair() {

		boolean result = false;
		try {
			KeyPair keyPair = KeyPair.genKeyPair(ssh, KeyPair.RSA, 1024);

			keyPair.writePublicKey(this.publicKeyPath.toString(), this.클라이언트아이디);
			keyPair.writePrivateKey(this.privateKeyPath.toString());
			result = true;

			logger.info("key generated : {}", keyPair.getFingerPrint());

			updateIdentity();

		} catch (JSchException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return result;
	}


	/**
	 * 파일 전송
	 * @param host
	 * @param port
	 * @param froms 전송할 파일 목록, 디렉토리가 ../* 로 끝나는 경우 해당 디렉토리의 모든 파일을 전송
	 * @param to
	 * @param username
	 * @param usePassword
	 * @param password
	 * @return 전송 실패한 파일 목록
	 */
	public List<String> sendFile(String host, int port, String[] froms, String to, String username, boolean usePassword, final String password) {

		Session session = null;
		ChannelSftp sftp = null;
		int retryMax = 10;

		List<String> failedList = new ArrayList<>(froms.length);

		try {
			session = ssh.getSession(username, host, port);
			if(usePassword) {
				session.setConfig("PreferredAuthentications", "password");
				session.setUserInfo(new AsdfUserInfo(password));
			}else {
				session.setConfig("PreferredAuthentications", "publickey");
			}

			session.connect(5 * 1000);

			sftp = (ChannelSftp) session.openChannel("sftp");
			sftp.connect(5 * 1000);

			for(String from : froms) {

				int retryCount = 0;
				boolean send = false;
				do {

					/* 재시도의 경우 3초간 대기 */
					if(retryCount > 0) {

						logger.warn("retry send file {} : {} -> {}", retryCount, from, to);
						try {
							Thread.sleep(3000);
						} catch (InterruptedException e) {
							e.printStackTrace();
						}
					}
					try {
						sftp.put(from, to, new SftpProgressMonitor() {

							private long sendBytes;

							@Override
							public void init(int op, String src, String dest, long max) {
								logger.info("send file : {} -> {} ", src, dest);
							}

							@Override
							public void end() {
								logger.info("send complete");
							}

							@Override
							public boolean count(long count) {
								sendBytes += count;

								//logger.debug("sendBytes {} total {}", count, sendBytes);

								return true;
							}
						}, ChannelSftp.OVERWRITE);
						send = true;
					} catch (SftpException e) {
						e.printStackTrace();
					}
				}while(!send && retryCount++ < retryMax);

				if(!send) {
					failedList.add(from);
				}
			}

		} catch (JSchException e) {
			e.printStackTrace();
		} finally {
			if(sftp != null && sftp.isConnected()) {
				sftp.quit();
			}
			if(session != null && session.isConnected()) {
				session.disconnect();
			}
		}

		return failedList;
	}

	/**
	 * @param sshConfigPath the sshConfigPath to set
	 */
	public void setSshConfigPath(Path sshConfigPath) {
		this.sshConfigPath = sshConfigPath;
	}

	/**
	 * @return the publicKeyPath
	 */
	public Path getPublicKeyPath() {
		return publicKeyPath;
	}

	/**
	 * 디렉토리를 조회한다
	 * @param host
	 * @param port
	 * @param username
	 * @param path
	 * @return 디렉토리의 파일 목록
	 */
	public List<String> list(String host, int port, String username, String path) {
		Session session = null;
		ChannelSftp sftp = null;
		final List<String> files = new ArrayList<String>(100);

		try {
			session = ssh.getSession(username, host, port);
			session.setConfig("PreferredAuthentications", "publickey");
			session.connect(5 * 1000);
			sftp = (ChannelSftp) session.openChannel("sftp");
			sftp.connect(5 * 1000);
			sftp.ls(path, new LsEntrySelector() {

				@Override
				public int select(LsEntry entry) {
					files.add(entry.getFilename());
					return LsEntrySelector.CONTINUE;
				}
			});
		} catch (JSchException e) {
			e.printStackTrace();
		} catch (SftpException e) {
			e.printStackTrace();
		} finally {
			if(sftp != null && sftp.isConnected()) {
				sftp.quit();
			}
			if(session != null && session.isConnected()) {
				session.disconnect();
			}
		}

		return files;
	}

	public boolean get(String host, int port, String username, String from, String to) {
		Session session = null;
		ChannelSftp sftp = null;

		try {
			session = ssh.getSession(username, host, port);
			session.setConfig("PreferredAuthentications", "publickey");
			session.connect(5 * 1000);
			sftp = (ChannelSftp) session.openChannel("sftp");
			sftp.connect(5 * 1000);

			sftp.get(from, to, new SftpProgressMonitor() {

				@Override
				public void init(int op, String src, String dest, long max) {
					logger.info("recv file : {} -> {} ", src, dest);
				}

				@Override
				public void end() {
					logger.info("recv complete");
				}

				@Override
				public boolean count(long count) {
					return true;
				}
			});

		} catch (JSchException e) {
			e.printStackTrace();
		} catch (SftpException e) {
			e.printStackTrace();
		} finally {
			if(sftp != null && sftp.isConnected()) {
				sftp.quit();
			}
			if(session != null && session.isConnected()) {
				session.disconnect();
			}
		}

		return true;
	}

	public boolean exists(String host, int port, String username, String path,final String file) {
		final int[] exists = new int[] { 0 };

		Session session = null;
		ChannelSftp sftp = null;

		try {
			session = ssh.getSession(username, host, port);
			session.setConfig("PreferredAuthentications", "publickey");
			session.connect(5 * 1000);
			sftp = (ChannelSftp) session.openChannel("sftp");
			sftp.connect(5 * 1000);

			sftp.ls(path, new LsEntrySelector() {

				@Override
				public int select(LsEntry entry) {
					if(file.contentEquals(entry.getFilename())) {
						exists[0] = 1;
						return LsEntrySelector.BREAK;
					}
					return LsEntrySelector.CONTINUE;
				}
			});
		} catch (JSchException e) {
			e.printStackTrace();
		} catch (SftpException e) {
			e.printStackTrace();
		} finally {
			if(sftp != null && sftp.isConnected()) {
				sftp.quit();
			}
			if(session != null && session.isConnected()) {
				session.disconnect();
			}
		}

		return exists[0] == 1;
	}

}



class AsdfUserInfo implements UserInfo {

	private final String password;

	public AsdfUserInfo(String password) {
		this.password = password;
	}

	@Override
	public String getPassphrase() {
		return null;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public boolean promptPassword(String message) {
		return true;
	}

	@Override
	public boolean promptPassphrase(String message) {
		return false;
	}

	@Override
	public boolean promptYesNo(String message) {
		System.out.println("promptYesNo " + message);
		return true;
	}

	@Override
	public void showMessage(String message) {
		System.out.println("showMessage " + message);
	}
}



class JschLogger implements com.jcraft.jsch.Logger {

	private Logger logger;
	public JschLogger(Logger logger) {
		this.logger = logger;
	}
	@Override
	public void log(int level, String message) {
		switch(level) {
		case com.jcraft.jsch.Logger.DEBUG:
			logger.debug(message);
			break;
		case com.jcraft.jsch.Logger.INFO:
			logger.info(message);
			break;
		case com.jcraft.jsch.Logger.WARN:
			logger.warn(message);
			break;
		case com.jcraft.jsch.Logger.ERROR:
			logger.error(message);
			break;
		case com.jcraft.jsch.Logger.FATAL:
			logger.fatal(message);
			break;
		default:

		}
	}

	@Override
	public boolean isEnabled(int level) {
		switch(level) {
		case com.jcraft.jsch.Logger.DEBUG:
			return logger.isDebugEnabled();
		case com.jcraft.jsch.Logger.INFO:
			return logger.isInfoEnabled();
		case com.jcraft.jsch.Logger.WARN:
			return logger.isWarnEnabled();
		case com.jcraft.jsch.Logger.ERROR:
			return logger.isErrorEnabled();
		case com.jcraft.jsch.Logger.FATAL:
			return logger.isFatalEnabled();
		default:
			return false;
		}
	}
}
