package org.springframework.security.acls.mongodb.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.mongodb.dao.AclClassRepository;
import org.springframework.security.acls.mongodb.dao.AclEntryRepository;
import org.springframework.security.acls.mongodb.dao.AclObjectIdentityRepository;
import org.springframework.security.acls.mongodb.dao.AclSidRepository;
import org.springframework.security.acls.mongodb.exception.ObjectClassNotExistException;
import org.springframework.security.acls.mongodb.model.AclClass;
import org.springframework.security.acls.mongodb.model.AclEntry;
import org.springframework.security.acls.mongodb.model.AclObjectIdentity;
import org.springframework.security.acls.mongodb.model.AclSid;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.mongodb.Mongo;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/applicationContext.xml")
public class MongodbAclServiceTest {
	
	private static CacheManager cacheManager;

	@Autowired
	private MongoOperations mongoTemplate;
	
	@Autowired
	private Mongo mongo;
	
	@Autowired
	private AclEntryRepository aclEntryRepository;
	
	@Autowired
	private AclObjectIdentityRepository objectIdentityRepository;
	
	@Autowired
	private AclSidRepository aclSidRepository;
	
	@Autowired
	private AclClassRepository aclClassRepository;
	
	private MongodbAclService mongodbAclService;
	
	@BeforeClass
	public static void setup() {
		cacheManager = new CacheManager();
		cacheManager.addCache(new Cache("basiclookuptestcache", 500, false, false, 30, 30));
	}
	
	@AfterClass
    public static void shutdownCacheManager() {
		cacheManager.removalAll();
        cacheManager.shutdown();
    }

	@SuppressWarnings("deprecation")
	@Before
	public void initBeans() {
        AclAuthorizationStrategy authorizationStrategy = new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"));
        EhCacheBasedAclCache cache = new EhCacheBasedAclCache(getCache());
		mongodbAclService = new MongodbAclService(
				aclEntryRepository, 
				objectIdentityRepository, 
				aclSidRepository,
				new SimpleCacheAclClassService(aclClassRepository), 
				cache, 
				authorizationStrategy, 
				new DefaultPermissionFactory(), 
				new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()));
		seedMongodbData();
	}
	
	private void seedMongodbData() {
		AclSid sid1 = new AclSid();
		sid1.setSid("1");
		sid1.setPrincipal(true);
		mongoTemplate.save(sid1);
		
		AclSid sid2 = new AclSid();
		sid2.setSid("2");
		sid2.setPrincipal(true);
		mongoTemplate.save(sid2);
		
		AclSid sid3 = new AclSid();
		sid3.setSid("3");
		sid3.setPrincipal(true);
		mongoTemplate.save(sid3);
		
		final String OBJECT_CLASS = "blog.core.Post";
		AclClass objectClass = new AclClass();
		objectClass.setClassName(OBJECT_CLASS);
		mongoTemplate.save(objectClass);
		
		AclObjectIdentity aoi1 = new AclObjectIdentity();
		aoi1.setObjectIdClass(objectClass.getId());
		aoi1.setObjectIdIdentity("1");
		aoi1.setOwnerId(sid1.getId());
		mongoTemplate.save(aoi1);
		
		AclObjectIdentity aoi2 = new AclObjectIdentity();
		aoi2.setObjectIdClass(objectClass.getId());
		aoi2.setObjectIdIdentity("2");
		aoi2.setOwnerId(sid1.getId());
		aoi2.setParentObjectId(aoi1.getId());
		mongoTemplate.save(aoi2);
		
		AclObjectIdentity aoi3 = new AclObjectIdentity();
		aoi3.setObjectIdClass(objectClass.getId());
		aoi3.setObjectIdIdentity("3");
		aoi3.setOwnerId(sid1.getId());
		aoi3.setParentObjectId(aoi1.getId());
		mongoTemplate.save(aoi3);
		
		AclObjectIdentity aoi4 = new AclObjectIdentity();
		aoi4.setObjectIdClass(objectClass.getId());
		aoi4.setObjectIdIdentity("4");
		aoi4.setOwnerId(sid1.getSid());
		aoi4.setParentObjectId(aoi1.getId());
		mongoTemplate.save(aoi4);
		
		AclEntry entry1 = new AclEntry();
		entry1.setObjectIdentityId(aoi1.getId());
		entry1.setSid(sid1.getId());
		entry1.setOrder(1);
		mongoTemplate.save(entry1);
		
		AclEntry entry2 = new AclEntry();
		entry2.setObjectIdentityId(aoi1.getId());
		entry2.setSid(sid2.getId());
		entry2.setOrder(1);
		mongoTemplate.save(entry2);
		
		AclEntry entry3 = new AclEntry();
		entry3.setObjectIdentityId(aoi1.getId());
		entry3.setSid(sid3.getId());
		entry3.setOrder(1);
		mongoTemplate.save(entry3);
	}
	
	private Ehcache getCache() {
        Ehcache cache = cacheManager.getCache("basiclookuptestcache");
        cache.removeAll();
        return cache;
    }
	
	@After
	public void cleanUpMongodbData() {
		mongo.dropDatabase("spring_security_acl_mongo_test");
	}

	@Test
	public void findChildren_WithValidObjectClass_ReturnData() throws Exception {
		ObjectIdentity parentIdentity = new ObjectIdentityImpl("blog.core.Post", "1");
		List<ObjectIdentity> children = mongodbAclService.findChildren(parentIdentity);
		assertNotNull("children should not be null", children);
		assertEquals(3, children.size());
		assertEquals(true, children.contains(new ObjectIdentityImpl("blog.core.Post", "2")));
		assertEquals(true, children.contains(new ObjectIdentityImpl("blog.core.Post", "3")));
		assertEquals(true, children.contains(new ObjectIdentityImpl("blog.core.Post", "4")));
	}
	
	@Test(expected = ObjectClassNotExistException.class)
	public void findChildren_WithNonExistedObjectClass_ThrowException() throws Exception {
		// arrange 
		ObjectIdentity parentIdentity = new ObjectIdentityImpl("blog.core.NonExisted", "1");

		// action
		mongodbAclService.findChildren(parentIdentity);
		
		// verify
	}
	
	@Test
	public void readAclById_ValidObjectIdentity_ReturnData() throws Exception {
		// arrange 
		ObjectIdentity objectIdentity = new ObjectIdentityImpl("blog.core.Post", "1");

		// action
		Acl acl = mongodbAclService.readAclById(objectIdentity);
		
		// verify
		assertNotNull("Acl should not be null", acl);
		ObjectIdentity result = acl.getObjectIdentity();
		assertEquals(result.getIdentifier(), objectIdentity.getIdentifier());
		assertEquals(result.getType(), objectIdentity.getType());
		
		List<AccessControlEntry> entries = acl.getEntries();
		assertNotNull("Acl entries list should not be null", entries);
		assertEquals(3, entries.size());
	}
}
