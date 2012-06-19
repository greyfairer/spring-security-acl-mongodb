package org.springframework.security.acls.mongodb.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

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
import org.springframework.security.acls.TargetObject;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.mongodb.dao.AclClassRepository;
import org.springframework.security.acls.mongodb.dao.AclEntryRepository;
import org.springframework.security.acls.mongodb.dao.AclObjectIdentityRepository;
import org.springframework.security.acls.mongodb.dao.AclSidRepository;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.mongodb.Mongo;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/applicationContext.xml")
public class MongodbMutableAclServiceTest {
	
	private static final String TARGET_CLASS = TargetObject.class.getName();

    private final Authentication auth = new TestingAuthenticationToken("tinh", "ignored","ROLE_ADMINISTRATOR");
    
    private final ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, "100");
    private final ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, "101");
    private final ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, "102");
	
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
	
	private MongodbMutableAclService mongodbMutableAclService;
	
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
        AclAuthorizationStrategy authorizationStrategy = new AclAuthorizationStrategyImpl(
        		new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"),
        		new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"),
        		new SimpleGrantedAuthority("ROLE_ADMINISTRATOR")
        		);
        EhCacheBasedAclCache cache = new EhCacheBasedAclCache(getCache());
        mongodbMutableAclService = new MongodbMutableAclService(
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
	
	private Ehcache getCache() {
        Ehcache cache = cacheManager.getCache("basiclookuptestcache");
        cache.removeAll();
        return cache;
    }
	
	private void seedMongodbData() {
		
	}
	
	@After
	public void cleanUpMongodbData() {
		mongo.dropDatabase("spring_security_acl_mongo_test");
	}
	
	@Test
	public void createAcl_ValidData_PersistedInDatastore() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		MutableAcl topParent = mongodbMutableAclService.createAcl(topParentOid);
        MutableAcl middleParent = mongodbMutableAclService.createAcl(middleParentOid);
        MutableAcl child = mongodbMutableAclService.createAcl(childOid);

        // Specify the inheritance hierarchy
        middleParent.setParent(topParent);
        child.setParent(middleParent);

        // Now let's add a couple of permissions
        topParent.insertAce(0, BasePermission.READ, new PrincipalSid(auth), true);
        topParent.insertAce(1, BasePermission.WRITE, new PrincipalSid(auth), false);
        middleParent.insertAce(0, BasePermission.DELETE, new PrincipalSid(auth), true);
        child.insertAce(0, BasePermission.DELETE, new PrincipalSid(auth), false);

        // Explicitly save the changed ACL
        mongodbMutableAclService.updateAcl(topParent);
        mongodbMutableAclService.updateAcl(middleParent);
        mongodbMutableAclService.updateAcl(child);

        // Let's check if we can read them back correctly
        Map<ObjectIdentity, Acl> map = mongodbMutableAclService.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid));
        assertEquals(3, map.size());

        // Replace our current objects with their retrieved versions
        topParent = (MutableAcl) map.get(topParentOid);
        middleParent = (MutableAcl) map.get(middleParentOid);
        child = (MutableAcl) map.get(childOid);

        // Check the retrieved versions has IDs
        assertNotNull(topParent.getId());
        assertNotNull(middleParent.getId());
        assertNotNull(child.getId());

        // Check their parents were correctly persisted
        assertNull(topParent.getParentAcl());
        assertEquals(topParentOid, middleParent.getParentAcl().getObjectIdentity());
        assertEquals(middleParentOid, child.getParentAcl().getObjectIdentity());

        // Check their ACEs were correctly persisted
        assertEquals(2, topParent.getEntries().size());
        assertEquals(1, middleParent.getEntries().size());
        assertEquals(1, child.getEntries().size());

        // Check the retrieved rights are correct
        List<Permission> read = Arrays.asList(BasePermission.READ);
        List<Permission> write = Arrays.asList(BasePermission.WRITE);
        List<Permission> delete = Arrays.asList(BasePermission.DELETE);
        List<Sid> pSid = Arrays.asList((Sid)new PrincipalSid(auth));


        assertTrue(topParent.isGranted(read, pSid, false));
        assertFalse(topParent.isGranted(write, pSid, false));
        assertTrue(middleParent.isGranted(delete, pSid, false));
        assertFalse(child.isGranted(delete, pSid, false));

        try {
            child.isGranted(Arrays.asList(BasePermission.ADMINISTRATION), pSid, false);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        // Now check the inherited rights (when not explicitly overridden) also look OK
        assertTrue(child.isGranted(read, pSid, false));
        assertFalse(child.isGranted(write, pSid, false));
        assertFalse(child.isGranted(delete, pSid, false));

        // Next change the child so it doesn't inherit permissions from above
        child.setEntriesInheriting(false);
        mongodbMutableAclService.updateAcl(child);
        child = (MutableAcl) mongodbMutableAclService.readAclById(childOid);
        assertFalse(child.isEntriesInheriting());

        // Check the child permissions no longer inherit
        assertFalse(child.isGranted(delete, pSid, true));

        try {
            child.isGranted(read, pSid, true);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        try {
            child.isGranted(write, pSid, true);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        // Let's add an identical permission to the child, but it'll appear AFTER the current permission, so has no impact
        child.insertAce(1, BasePermission.DELETE, new PrincipalSid(auth), true);

        // Let's also add another permission to the child
        child.insertAce(2, BasePermission.CREATE, new PrincipalSid(auth), true);

        // Save the changed child
        mongodbMutableAclService.updateAcl(child);
        child = (MutableAcl) mongodbMutableAclService.readAclById(childOid);
        assertEquals(3, child.getEntries().size());

        // Output permissions
        for (int i = 0; i < child.getEntries().size(); i++) {
            System.out.println(child.getEntries().get(i));
        }

        // Check the permissions are as they should be
        assertFalse(child.isGranted(delete, pSid, true)); // as earlier permission overrode
        assertTrue(child.isGranted(Arrays.asList(BasePermission.CREATE), pSid, true));

        // Now check the first ACE (index 0) really is DELETE for our Sid and is non-granting
        AccessControlEntry entry = child.getEntries().get(0);
        assertEquals(BasePermission.DELETE.getMask(), entry.getPermission().getMask());
        assertEquals(new PrincipalSid(auth), entry.getSid());
        assertFalse(entry.isGranting());
        assertNotNull(entry.getId());

        // Now delete that first ACE
        child.deleteAce(0);

        // Save and check it worked
        child = mongodbMutableAclService.updateAcl(child);
        assertEquals(2, child.getEntries().size());
        assertTrue(child.isGranted(delete, pSid, false));

        SecurityContextHolder.clearContext();
	}
}
