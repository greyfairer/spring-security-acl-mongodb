package org.springframework.security.acls.mongodb.service;

import java.io.IOException;
import java.net.UnknownHostException;

import de.flapdoodle.embedmongo.MongoDBRuntime;
import de.flapdoodle.embedmongo.MongodExecutable;
import de.flapdoodle.embedmongo.MongodProcess;
import de.flapdoodle.embedmongo.config.MongodConfig;
import de.flapdoodle.embedmongo.distribution.Version;
import de.flapdoodle.embedmongo.runtime.Network;

public class EmbeddedMongodbHelper {
	private int port;
	
	private MongodProcess mongod;
	private MongodExecutable mongodExe;
	
	public EmbeddedMongodbHelper(int port, Version version) throws UnknownHostException {
		super();
		this.port = port;
		
		MongoDBRuntime runtime = MongoDBRuntime.getDefaultInstance();
		mongodExe = runtime.prepare(new MongodConfig(version, this.port, Network.localhostIsIPv6()));
	}
	
	public void start() throws IOException {
		mongod = mongodExe.start();
	}
	
	public void stop() {
		mongod.stop();
		mongodExe.cleanup();
	}
}
