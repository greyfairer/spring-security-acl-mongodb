package org.springframework.security.acls.mongodb.model;

import static com.mysema.query.types.PathMetadataFactory.*;

import com.mysema.query.types.*;
import com.mysema.query.types.path.*;

import javax.annotation.Generated;


/**
 * QAclSid is a Querydsl query type for AclSid
 */
@Generated("com.mysema.query.codegen.EntitySerializer")
public class QAclSid extends EntityPathBase<AclSid> {

    private static final long serialVersionUID = 1615010979;

    public static final QAclSid aclSid = new QAclSid("aclSid");

    public final StringPath id = createString("id");

    public final BooleanPath principal = createBoolean("principal");

    public final StringPath sid = createString("sid");

    public QAclSid(String variable) {
        super(AclSid.class, forVariable(variable));
    }

    public QAclSid(Path<? extends AclSid> entity) {
        super(entity.getType(), entity.getMetadata());
    }

    public QAclSid(PathMetadata<?> metadata) {
        super(AclSid.class, metadata);
    }

}

