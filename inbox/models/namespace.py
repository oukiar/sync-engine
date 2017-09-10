from sqlalchemy import Column, BigInteger, ForeignKey, bindparam
from sqlalchemy.orm import relationship, backref

from inbox.models.base import MailSyncBase
from inbox.models.mixins import HasPublicID, UpdatedAtMixin, DeletedAtMixin
from inbox.sqlalchemy_ext.util import bakery

from sync_timeouts import mailboxes_timeouts

class Namespace(MailSyncBase, HasPublicID, UpdatedAtMixin, DeletedAtMixin):
    account_id = Column(BigInteger,
                        ForeignKey('account.id', ondelete='CASCADE'),
                        nullable=True)
    account = relationship('Account',
                           lazy='joined',
                           single_parent=True,
                           backref=backref('namespace',
                                           uselist=False,
                                           lazy='joined',
                                           passive_deletes=True,
                                           cascade='all,delete-orphan'),
                           uselist=False)

    def __str__(self):
        return "{} <{}>".format(self.public_id, self.account.email_address if
                                self.account else '')

    @property
    def email_address(self):
        if self.account is not None:
            return self.account.email_address

    @classmethod
    def get(cls, id_, session):
        #print('getting ID')
        q = bakery(lambda session: session.query(cls))
        q += lambda q: q.filter(cls.id == bindparam('id_'))
        return q(session).params(id_=id_).first()

    @classmethod
    def from_public_id(cls, public_id, db_session):
        q = bakery(lambda session: session.query(Namespace))
        q += lambda q: q.filter(
            Namespace.public_id == bindparam('public_id'))
        return q(db_session).params(public_id=public_id).one()

    def get_syncing_mailboxes(self):
        result = []
        for i in mailboxes_timeouts:
            if self.account.email_address in i:
                result.append( i.split(':')[1] )
                
        return result
        
        
