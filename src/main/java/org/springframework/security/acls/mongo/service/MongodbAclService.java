package org.springframework.security.acls.mongo.service;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.UnloadedSidException;
import org.springframework.security.acls.mongo.dao.AclEntryRepository;
import org.springframework.security.acls.mongo.dao.AclObjectIdentityRepository;
import org.springframework.security.acls.mongo.dao.AclSidRepository;
import org.springframework.security.acls.mongo.model.AclEntry;
import org.springframework.security.acls.mongo.model.AclObjectIdentity;
import org.springframework.security.acls.mongo.model.AclSid;
import org.springframework.security.acls.mongo.model.QAclEntry;
import org.springframework.security.acls.mongo.model.QAclObjectIdentity;
import org.springframework.security.util.FieldUtils;
import org.springframework.util.Assert;

import com.mysema.query.types.expr.BooleanExpression;

public class MongodbAclService implements AclService {

	protected AclObjectIdentityRepository objectIdentityRepository;
	protected AclEntryRepository aclEntryRepository;
	protected AclSidRepository sidRepository;
	protected AclClassService aclClassService;
	protected final AclCache aclCache;
	protected final AclAuthorizationStrategy aclAuthorizationStrategy;
	protected PermissionFactory permissionFactory = new DefaultPermissionFactory();
	protected final PermissionGrantingStrategy grantingStrategy;
	
	protected final Field fieldAces = FieldUtils.getField(AclImpl.class, "aces");
	protected final Field fieldAcl = FieldUtils.getField(AccessControlEntryImpl.class, "acl");

	public MongodbAclService(AclEntryRepository aclEntryRepository,
			AclObjectIdentityRepository objectIdentityRepository,
			AclClassService aclClassService,
			AclCache aclCache,
			AclAuthorizationStrategy aclAuthorizationStrategy,
			PermissionFactory permissionFactory,
			PermissionGrantingStrategy grantingStrategy) {
		super();
		this.aclEntryRepository = aclEntryRepository;
		this.objectIdentityRepository = objectIdentityRepository;
		this.aclClassService = aclClassService;
		this.aclCache = aclCache;
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
		this.permissionFactory = permissionFactory;
		this.grantingStrategy = grantingStrategy;
		
		this.fieldAces.setAccessible(true);
	}

	@Override
	public List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity) {
		String objectClassId = aclClassService.getObjectClassId(parentIdentity.getType());
		QAclObjectIdentity aclObjectIdentity = QAclObjectIdentity.aclObjectIdentity;
		Iterator<AclObjectIdentity> aois = objectIdentityRepository.findAll(
				aclObjectIdentity.parentObjectId.eq(
						(String) parentIdentity.getIdentifier()).and(
						aclObjectIdentity.objectIdClass.eq(objectClassId)))
				.iterator();
		List<ObjectIdentity> results = new ArrayList<ObjectIdentity>();
		while (aois.hasNext()) {
			AclObjectIdentity objectIdentity = aois.next();
			results.add(new ObjectIdentityImpl(parentIdentity.getType(),
					objectIdentity.getId()));
		}
		if (results.size() == 0)
			return null;

		return results;
	}

	@Override
	public Acl readAclById(ObjectIdentity object, List<Sid> sids)
			throws NotFoundException {
		Map<ObjectIdentity, Acl> map = readAclsById(Arrays.asList(object), sids);
		Assert.isTrue(map.containsKey(object),
				"There should have been an Acl entry for ObjectIdentity "
						+ object);

		return (Acl) map.get(object);
	}

	@Override
	public Acl readAclById(ObjectIdentity object) throws NotFoundException {
		return readAclById(object, null);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects)
			throws NotFoundException {
		return readAclsById(objects, null);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects,
			List<Sid> sids) throws NotFoundException {
		Map<ObjectIdentity, Acl> result = doLookup(objects, sids);

		// Check every requested object identity was found (throw
		// NotFoundException if needed)
		for (ObjectIdentity oid : objects) {
			if (!result.containsKey(oid)) {
				throw new NotFoundException("Unable to find ACL information for object identity '" + oid + "'");
			}
		}

		return result;

	}

	private Map<ObjectIdentity, Acl> doLookup(List<ObjectIdentity> objects,
			List<Sid> sids) {
		Assert.notEmpty(objects, "Objects to lookup required");

		// Map<ObjectIdentity,Acl>
		Map<ObjectIdentity, Acl> result = new HashMap<ObjectIdentity, Acl>(); // contains FULLY loaded Acl objects

		Set<ObjectIdentity> oidToLoad = new HashSet<ObjectIdentity>();

		for (int i = 0; i < objects.size(); i++) {
			final ObjectIdentity oid = objects.get(i);
			boolean aclFound = false;

			Acl acl = aclCache.getFromCache(oid);

			// Ensure any cached element supports all the requested SIDs
			// (they should always, as our base impl doesn't filter on SID)
			if (acl != null) {
				if (acl.isSidLoaded(sids)) {
					result.put(acl.getObjectIdentity(), acl);
					aclFound = true;
				} else {
					throw new IllegalStateException(
							"Error: SID-filtered element detected when implementation does not perform SID filtering "
									+ "- have you added something to the cache manually?");
				}
			}

			// Load the ACL from the database
			if (!aclFound) {
				oidToLoad.add(oid);
			}
		}

		// Is it time to load from Mongodb
		if (oidToLoad.size() > 0) {
			result = lookupObjectIdentities(oidToLoad, sids);

			// Add the loaded Acl to the cache
			for (Acl loadedAcl : result.values()) {
				aclCache.putInCache((AclImpl) loadedAcl);
			}
		}

		return result;
	}

	private Map<ObjectIdentity, Acl> lookupObjectIdentities(final Collection<ObjectIdentity> objectIdentities, List<Sid> sids) {
		Assert.notEmpty(objectIdentities, "Must provide identities to lookup");

		final Map<Serializable, Acl> acls = new HashMap<Serializable, Acl>(); // contains Acls with StubAclParents
		QAclObjectIdentity aclObjectIdentity = QAclObjectIdentity.aclObjectIdentity;
		BooleanExpression objectIdentityCondition = null;
		for (ObjectIdentity oid : objectIdentities) {
			BooleanExpression oidCondition = aclObjectIdentity.objectIdIdentity
					.eq((String) oid.getIdentifier()).and(
							aclObjectIdentity.objectIdClass.eq(oid.getType()));
			if (objectIdentityCondition == null) {
				objectIdentityCondition = oidCondition;
			} else {
				objectIdentityCondition.or(oidCondition);
			}
		}
		List<AclObjectIdentity> aoiList = (List<AclObjectIdentity>) objectIdentityRepository
				.findAll(objectIdentityCondition, aclObjectIdentity.objectIdIdentity.asc());
		
		
		Set<String> parentAclIds = getParentIdsToLookup(acls, aoiList, sids);
		
		if (parentAclIds.size() > 0) {
			lookUpParentAcls(acls, parentAclIds, sids);
		}

		// Finally, convert our "acls" containing StubAclParents into true Acls
		Map<ObjectIdentity, Acl> resultMap = new HashMap<ObjectIdentity, Acl>();
		for (Acl inputAcl : acls.values()) {
            Assert.isInstanceOf(AclImpl.class, inputAcl, "Map should have contained an AclImpl");
            Assert.isInstanceOf(String.class, ((AclImpl) inputAcl).getId(), "Acl.getId() must be String");

            Acl result = convert(acls, (String)((AclImpl) inputAcl).getId());
            resultMap.put(result.getObjectIdentity(), result);
        }
		return resultMap;
	}
	
	private Set<String> getParentIdsToLookup(Map<Serializable, Acl> acls, List<AclObjectIdentity> aoiList, List<Sid> sids) {
		List<String> objectIdentityIds = new ArrayList<String>();
		Set<String> parentIdsToLookup = new HashSet<String>();
		for (AclObjectIdentity aoi : aoiList) {
			objectIdentityIds.add(aoi.getId());
			String parentId = aoi.getParentObjectId();
			if (parentId != null) {
				if (!acls.containsKey(parentId)) {
					// Now try to find it in the cache
                    MutableAcl cached = aclCache.getFromCache(new Long(parentId));

                    if ((cached == null) || !cached.isSidLoaded(sids)) {
                        parentIdsToLookup.add(parentId);
                    } else {
                        // Pop into the acls map, so our convert method doesn't
                        // need to deal with an unsynchronized AclCache
                        acls.put(cached.getId(), cached);
                    }

					parentIdsToLookup.add(aoi.getParentObjectId());
				}
			}
		}
		 
		List<AclEntry> entries = getAssociatedAclEntries(objectIdentityIds);
		for (AclObjectIdentity aoi : aoiList) {
			convertObjectIdentityIntoAclObject(acls, aoi, entries);
		}
		return parentIdsToLookup;
	}
	
	private List<AclEntry> getAssociatedAclEntries(List<String> objectIdentityIds) {
		BooleanExpression aclEntryCondition = null;
		for (String oid : objectIdentityIds) {
			BooleanExpression oidCondition = QAclEntry.aclEntry.objectIdentityId.eq(oid);
			if (aclEntryCondition == null) {
				aclEntryCondition = oidCondition;
			} else {
				aclEntryCondition.or(oidCondition);
			}
		}

		List<AclEntry> aclEntries = (List<AclEntry>) aclEntryRepository.findAll(aclEntryCondition, QAclEntry.aclEntry.order.asc());
		return aclEntries;
	}
	
	private void lookUpParentAcls(Map<Serializable, Acl> acls, Set<String> parentIds, List<Sid> sids) {
		QAclObjectIdentity aclObjectIdentity = QAclObjectIdentity.aclObjectIdentity;
		BooleanExpression objectIdentityCondition = null;
		for (String oid : parentIds) {
			BooleanExpression oidCondition = aclObjectIdentity.id.eq(oid);
			if (objectIdentityCondition == null) {
				objectIdentityCondition = oidCondition;
			} else {
				objectIdentityCondition.or(oidCondition);
			}
		}
		List<AclObjectIdentity> aoiList = (List<AclObjectIdentity>) objectIdentityRepository
				.findAll(objectIdentityCondition, aclObjectIdentity.objectIdIdentity.asc());
		Set<String> parentIdsToLookup = getParentIdsToLookup(acls, aoiList, sids);
		if (parentIdsToLookup != null && parentIdsToLookup.size() > 0) {
			lookUpParentAcls(acls, parentIdsToLookup, sids);
		}
	}
	
	@SuppressWarnings("unchecked")
    private List<AccessControlEntryImpl> readAces(AclImpl acl) {
        try {
            return (List<AccessControlEntryImpl>) fieldAces.get(acl);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Could not obtain AclImpl.aces field", e);
        }
    }

	private List<AclEntry> findAclEntryOfObjectIdentity(
			AclObjectIdentity objectIdentity, List<AclEntry> aclEntries) {
		List<AclEntry> result = new ArrayList<AclEntry>();
		for (AclEntry entry : aclEntries) {
			if (entry.getObjectIdentityId().equals(objectIdentity.getId())) {
				result.add(entry);
			}
		}
		Collections.sort(result, new Comparator<AclEntry>() {
			@Override
			public int compare(AclEntry o1, AclEntry o2) {
				return o1.getOrder() - o2.getOrder();
			}
		});
		return result;
	}

	private void convertObjectIdentityIntoAclObject(Map<Serializable, Acl> acls, AclObjectIdentity objectIdentity, List<AclEntry> aclEntries) {
		String id = objectIdentity.getId();
		Acl acl = acls.get(id);
		if (acl == null) {
			ObjectIdentity springOid = new ObjectIdentityImpl(
					objectIdentity.getObjectIdClass(),
					objectIdentity.getObjectIdIdentity());
			Acl parentAcl = null;
			if (objectIdentity.getParentObjectId() != null) {
				parentAcl = new StubAclParent(objectIdentity.getParentObjectId());
			}
			
			Sid owner = createSidFromMongoId(objectIdentity.getOwnerId());
			
			acl = new AclImpl(springOid, id, aclAuthorizationStrategy,
					grantingStrategy, parentAcl, null,
					objectIdentity.isEntriesInheriting(), owner);
			acls.put(id, acl);
		}
		
		List<AclEntry> belongedEntries = findAclEntryOfObjectIdentity(objectIdentity, aclEntries);
		for (AclEntry entry : belongedEntries) {
			if (entry.getSid() != null) {
				AccessControlEntryImpl ace = convertAclEntryIntoObject(acl, entry);
				List<AccessControlEntryImpl> aces = readAces((AclImpl)acl);

                // Add the ACE if it doesn't already exist in the ACL.aces field
                if (!aces.contains(ace)) {
                    aces.add(ace);
                }
			}
		}
	}
	
	private AccessControlEntryImpl convertAclEntryIntoObject(Acl acl, AclEntry aclEntry) {
		String aceId = aclEntry.getId();
		Sid recipient = createSidFromMongoId(aclEntry.getSid());
		
		int mask = aclEntry.getMask();
        Permission permission = permissionFactory.buildFromMask(mask);
        boolean granting = aclEntry.isGranting();
        boolean auditSuccess = aclEntry.isAuditSuccess();
        boolean auditFailure = aclEntry.isAuditFailure();

        return new AccessControlEntryImpl(aceId, acl, recipient, permission, granting,
                auditSuccess, auditFailure);
	}
	
	private Sid createSidFromMongoId(String id) {
		Sid sid;
		AclSid aclSid = sidRepository.findOne(id);
		if (aclSid.isPrincipal()) {
			sid = new PrincipalSid(id);
		} else {
			sid = new GrantedAuthoritySid(id);
		}
		return sid;
	}
	
	private AclImpl convert(Map<Serializable, Acl> inputMap, String currentIdentity) {
        Assert.notEmpty(inputMap, "InputMap required");
        Assert.notNull(currentIdentity, "CurrentIdentity required");

        // Retrieve this Acl from the InputMap
        Acl uncastAcl = inputMap.get(currentIdentity);
        Assert.isInstanceOf(AclImpl.class, uncastAcl, "The inputMap contained a non-AclImpl");

        AclImpl inputAcl = (AclImpl) uncastAcl;

        Acl parent = inputAcl.getParentAcl();

        if ((parent != null) && parent instanceof StubAclParent) {
            // Lookup the parent
            StubAclParent stubAclParent = (StubAclParent) parent;
            parent = convert(inputMap, stubAclParent.getId());
        }

        // Now we have the parent (if there is one), create the true AclImpl
        AclImpl result = new AclImpl(inputAcl.getObjectIdentity(), (Long) inputAcl.getId(), aclAuthorizationStrategy,
                grantingStrategy, parent, null, inputAcl.isEntriesInheriting(), inputAcl.getOwner());

        // Copy the "aces" from the input to the destination

        // Obtain the "aces" from the input ACL
        List<AccessControlEntryImpl> aces = readAces(inputAcl);

        // Create a list in which to store the "aces" for the "result" AclImpl instance
        List<AccessControlEntryImpl> acesNew = new ArrayList<AccessControlEntryImpl>();

        // Iterate over the "aces" input and replace each nested AccessControlEntryImpl.getAcl() with the new "result" AclImpl instance
        // This ensures StubAclParent instances are removed, as per SEC-951
        for (AccessControlEntryImpl ace : aces) {
            setAclOnAce(ace, result);
            acesNew.add(ace);
        }

        // Finally, now that the "aces" have been converted to have the "result" AclImpl instance, modify the "result" AclImpl instance
        setAces(result, acesNew);

        return result;
    }
	
	private void setAclOnAce(AccessControlEntryImpl ace, AclImpl acl) {
        try {
            fieldAcl.set(ace, acl);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Could not or set AclImpl on AccessControlEntryImpl fields", e);
        }
    }

    private void setAces(AclImpl acl, List<AccessControlEntryImpl> aces) {
        try {
            fieldAces.set(acl, aces);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Could not set AclImpl entries", e);
        }
    }

	private class StubAclParent implements Acl {

		private static final long serialVersionUID = 8425727812609172852L;
		private final String id;

		public StubAclParent(String id) {
			this.id = id;
		}

		public List<AccessControlEntry> getEntries() {
			throw new UnsupportedOperationException("Stub only");
		}

		public String getId() {
			return id;
		}

		public ObjectIdentity getObjectIdentity() {
			throw new UnsupportedOperationException("Stub only");
		}

		public Sid getOwner() {
			throw new UnsupportedOperationException("Stub only");
		}

		public Acl getParentAcl() {
			throw new UnsupportedOperationException("Stub only");
		}

		public boolean isEntriesInheriting() {
			throw new UnsupportedOperationException("Stub only");
		}

		public boolean isGranted(List<Permission> permission, List<Sid> sids,
				boolean administrativeMode) throws NotFoundException,
				UnloadedSidException {
			throw new UnsupportedOperationException("Stub only");
		}

		public boolean isSidLoaded(List<Sid> sids) {
			throw new UnsupportedOperationException("Stub only");
		}
	}
}
