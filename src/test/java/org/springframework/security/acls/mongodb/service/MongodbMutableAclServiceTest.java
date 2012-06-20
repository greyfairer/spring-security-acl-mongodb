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
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.CumulativePermission;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.mongodb.dao.AclClassRepository;
import org.springframework.security.acls.mongodb.dao.AclEntryRepository;
import org.springframework.security.acls.mongodb.dao.AclObjectIdentityRepository;
import org.springframework.security.acls.mongodb.dao.AclSidRepository;
import org.springframework.security.acls.mongodb.model.AclClass;
import org.springframework.security.acls.mongodb.model.AclEntry;
import org.springframework.security.acls.mongodb.model.AclObjectIdentity;
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
	
	private EhCacheBasedAclCache cache;

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
        cache = new EhCacheBasedAclCache(getCache());
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
	
	@Test
    public void deleteAclAlsoDeletesChildren() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);

        mongodbMutableAclService.createAcl(topParentOid);
        MutableAcl middleParent = mongodbMutableAclService.createAcl(middleParentOid);
        MutableAcl child = mongodbMutableAclService.createAcl(childOid);
        child.setParent(middleParent);
        mongodbMutableAclService.updateAcl(middleParent);
        mongodbMutableAclService.updateAcl(child);
        // Check the childOid really is a child of middleParentOid
        Acl childAcl = mongodbMutableAclService.readAclById(childOid);

        assertEquals(middleParentOid, childAcl.getParentAcl().getObjectIdentity());

        // Delete the mid-parent and test if the child was deleted, as well
        mongodbMutableAclService.deleteAcl(middleParentOid, true);

        try {
            mongodbMutableAclService.readAclById(middleParentOid);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            assertTrue(true);
        }
        try {
            mongodbMutableAclService.readAclById(childOid);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            assertTrue(true);
        }

        Acl acl = mongodbMutableAclService.readAclById(topParentOid);
        assertNotNull(acl);
        assertEquals(((MutableAcl) acl).getObjectIdentity(), topParentOid);
    }
	
	@Test(expected = IllegalArgumentException.class)
    public void createAclRejectsNullParameter() throws Exception {
        mongodbMutableAclService.createAcl(null);
    }
	
	@Test(expected = AlreadyExistsException.class)
    public void createAclForADuplicateDomainObject() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);
        ObjectIdentity duplicateOid = new ObjectIdentityImpl(TARGET_CLASS, "100");
        mongodbMutableAclService.createAcl(duplicateOid);
        mongodbMutableAclService.createAcl(duplicateOid);
    }

    @Test(expected = IllegalArgumentException.class)
    public void deleteAclRejectsNullParameters() throws Exception {
    	mongodbMutableAclService.deleteAcl(null, true);
    }
    
    @Test
    public void deleteAclRemovesRowsFromDatabase() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);
        MutableAcl child = mongodbMutableAclService.createAcl(childOid);
        child.insertAce(0, BasePermission.DELETE, new PrincipalSid(auth), false);
        mongodbMutableAclService.updateAcl(child);

        // Remove the child and check all related database rows were removed accordingly
        mongodbMutableAclService.deleteAcl(childOid, false);
        
        assertEquals(1, mongoTemplate.findAll(AclClass.class).size());
        assertEquals(0, mongoTemplate.findAll(AclObjectIdentity.class).size());
        assertEquals(0, mongoTemplate.findAll(AclEntry.class).size());

        // Check the cache
        assertNull(cache.getFromCache(childOid));
        assertNull(cache.getFromCache("102"));
    }
    
    @Test
    public void childrenAreClearedFromCacheWhenParentIsUpdated() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored","ROLE_ADMINISTRATOR");
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity parentOid = new ObjectIdentityImpl(TARGET_CLASS, "104");
        ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, "105");

        MutableAcl parent = mongodbMutableAclService.createAcl(parentOid);
        MutableAcl child = mongodbMutableAclService.createAcl(childOid);

        child.setParent(parent);
        mongodbMutableAclService.updateAcl(child);

        parent = (AclImpl) mongodbMutableAclService.readAclById(parentOid);
        parent.insertAce(0, BasePermission.READ, new PrincipalSid("ben"), true);
        mongodbMutableAclService.updateAcl(parent);

        parent = (AclImpl) mongodbMutableAclService.readAclById(parentOid);
        parent.insertAce(1, BasePermission.READ, new PrincipalSid("scott"), true);
        mongodbMutableAclService.updateAcl(parent);

        child = (MutableAcl) mongodbMutableAclService.readAclById(childOid);
        parent = (MutableAcl) child.getParentAcl();

        assertEquals("Fails because child has a stale reference to its parent", 2, parent.getEntries().size());
        assertEquals(1, parent.getEntries().get(0).getPermission().getMask());
        assertEquals(new PrincipalSid("ben"), parent.getEntries().get(0).getSid());
        assertEquals(1, parent.getEntries().get(1).getPermission().getMask());
        assertEquals(new PrincipalSid("scott"), parent.getEntries().get(1).getSid());
    }
    
    @Test
    public void childrenAreClearedFromCacheWhenParentisUpdated2() throws Exception {
        Authentication auth = new TestingAuthenticationToken("system", "secret","ROLE_IGNORED");
        SecurityContextHolder.getContext().setAuthentication(auth);
        ObjectIdentityImpl rootObject = new ObjectIdentityImpl(TARGET_CLASS, "1");

        MutableAcl parent = mongodbMutableAclService.createAcl(rootObject);
        MutableAcl child = mongodbMutableAclService.createAcl(new ObjectIdentityImpl(TARGET_CLASS, "2"));
        child.setParent(parent);
        mongodbMutableAclService.updateAcl(child);

        parent.insertAce(0, BasePermission.ADMINISTRATION, new GrantedAuthoritySid("ROLE_ADMINISTRATOR"), true);
        mongodbMutableAclService.updateAcl(parent);

        parent.insertAce(1, BasePermission.DELETE, new PrincipalSid("terry"), true);
        mongodbMutableAclService.updateAcl(parent);

        child = (MutableAcl) mongodbMutableAclService.readAclById(new ObjectIdentityImpl(TARGET_CLASS, "2"));

        parent = (MutableAcl) child.getParentAcl();

        assertEquals(2, parent.getEntries().size());
        assertEquals(16, parent.getEntries().get(0).getPermission().getMask());
        assertEquals(new GrantedAuthoritySid("ROLE_ADMINISTRATOR"), parent.getEntries().get(0).getSid());
        assertEquals(8, parent.getEntries().get(1).getPermission().getMask());
        assertEquals(new PrincipalSid("terry"), parent.getEntries().get(1).getSid());
    }
    
    @Test
    public void cumulativePermissions() {
       Authentication auth = new TestingAuthenticationToken("ben", "ignored", "ROLE_ADMINISTRATOR");
       auth.setAuthenticated(true);
       SecurityContextHolder.getContext().setAuthentication(auth);

       ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, "110");
       MutableAcl topParent = mongodbMutableAclService.createAcl(topParentOid);

       // Add an ACE permission entry
       Permission cm = new CumulativePermission().set(BasePermission.READ).set(BasePermission.ADMINISTRATION);
       assertEquals(17, cm.getMask());
       Sid benSid = new PrincipalSid(auth);
       topParent.insertAce(0, cm, benSid, true);
       assertEquals(1, topParent.getEntries().size());

       // Explicitly save the changed ACL
       topParent = mongodbMutableAclService.updateAcl(topParent);

       // Check the mask was retrieved correctly
       assertEquals(17, topParent.getEntries().get(0).getPermission().getMask());
       assertTrue(topParent.isGranted(Arrays.asList(cm), Arrays.asList(benSid), true));

       SecurityContextHolder.clearContext();
   }
}
