from algopy import (
    Account,
    ARC4Contract,
    Bytes,
    Global,
    LocalState,
    OnCompleteAction,
    String,
    Txn,
    UInt64,
    op,
    subroutine,
)
from algopy.arc4 import abimethod


class Blockchainsmartcontract(ARC4Contract):
    def __init__(self) -> None:
        self.admin = Global.creator_address
        self.certificateID = LocalState(Bytes)
        self.language = LocalState(String)
        self.skill_level = LocalState(String)
        self.issue_date = LocalState(UInt64)
        self.expiry_date = LocalState(UInt64)
        self.issued_by = LocalState(Account)
        self.is_revoked = LocalState(UInt64)
        self.revocation_reason = LocalState(String)
        self.counterCertificates = UInt64(0)
        self.uniqueIDs = UInt64(0)

    @abimethod(allow_actions=[OnCompleteAction.OptIn])
    def opt_in(self) -> None:
        self.certificateID[Txn.sender] = Bytes()
        self.language[Txn.sender] = String("")
        self.skill_level[Txn.sender] = String("")
        self.issue_date[Txn.sender] = UInt64(0)
        self.expiry_date[Txn.sender] = UInt64(0)
        self.is_revoked[Txn.sender] = UInt64(0)
        self.revocation_reason[Txn.sender] = String("")

    @abimethod
    def issue_certificate(
        self,
        account: Account,
        language: String,
        skill_level: String,
    ) -> UInt64:
        assert Txn.sender == self.admin
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in to the application."
        assert not result, "Certificate already issued to this account."

        expiry_date = Global.latest_timestamp + 126227704
        encrypted_id = op.sha256(
            op.concat(
                op.concat(op.itob(self.uniqueIDs), op.itob(Global.latest_timestamp)),
                Txn.sender.bytes,
            )
        )
        self.certificateID[account] = encrypted_id
        self.language[account] = language
        self.skill_level[account] = skill_level
        self.issue_date[account] = Global.latest_timestamp
        self.expiry_date[account] = expiry_date
        self.issued_by[account] = Txn.sender
        self.is_revoked[account] = UInt64(0)
        self.revocation_reason[account] = String("")
        self.counterCertificates += 1
        self.uniqueIDs += 1

        return self.uniqueIDs - 1

    @abimethod(readonly=True)
    def view_certificate(
        self, account: Account
    ) -> tuple[Bytes, String, String, Bytes, String, String]:
        assert Txn.sender == account or Txn.sender == self.admin
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate"

        if Global.latest_timestamp < self.expiry_date[account]:
            expiration = String("Valid.")
        else:
            expiration = String("Expired.")

        if self.is_revoked[account] == 0:
            validity = String("Not revoked.")
        else:
            validity = String("Revoked.")

        return (
            account.bytes,
            self.language[account],
            self.skill_level[account],
            self.issued_by[account].bytes,
            expiration,
            validity,
        )

    @abimethod
    def update_level(self, account: Account, new_skill_level: String) -> None:
        assert Txn.sender == self.admin
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate."

        self.skill_level[account] = new_skill_level

    @abimethod
    def revoke_certificate(self, account: Account, reason: String) -> None:
        assert Txn.sender == self.admin
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate."
        assert self.is_revoked[account] == UInt64(0)

        self.is_revoked[account] = UInt64(1)
        self.counterCertificates -= 1
        self.revocation_reason[account] = reason

    @abimethod
    def valid_certificate(self, account: Account) -> None:
        assert Txn.sender == self.admin
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate."
        assert self.is_revoked[account] == UInt64(1)

        self.is_revoked[account] = UInt64(0)
        self.counterCertificates += 1
        self.revocation_reason[account] = String("")

    @abimethod
    def renew_certificate(self, account: Account) -> None:
        assert Txn.sender == self.admin
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate."
        assert (
            Global.latest_timestamp > self.expiry_date[account]
        ), "This certificate is not caducated."
        assert self.is_revoked[account] == UInt64(
            0
        ), "Cannot renew a revoked certificate."

        new_expiry_date = Global.latest_timestamp + 126227704
        self.expiry_date[account] = new_expiry_date

    @subroutine
    def delete_account(self, account: Account) -> None:
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate."
        del self.certificateID[account]
        del self.language[account]
        del self.skill_level[account]
        del self.issue_date[account]
        del self.expiry_date[account]
        del self.issued_by[account]
        del self.is_revoked[account]
        del self.revocation_reason[account]

    @abimethod
    def transfer_certificate(
        self, origin_account: Account, destination_account: Account
    ) -> None:
        assert Txn.sender == self.admin
        result, exists = self.certificateID.maybe(origin_account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate."
        exists_destination = self.certificateID.maybe(destination_account)
        assert exists_destination, "Account has not opted in."

        self.certificateID[destination_account] = self.certificateID[origin_account]
        self.language[destination_account] = self.language[origin_account]
        self.skill_level[destination_account] = self.skill_level[origin_account]
        self.issue_date[destination_account] = self.issue_date[origin_account]
        self.expiry_date[destination_account] = self.expiry_date[origin_account]
        self.issued_by[destination_account] = self.issued_by[origin_account]
        self.is_revoked[destination_account] = self.is_revoked[origin_account]
        self.revocation_reason[destination_account] = self.revocation_reason[
            origin_account
        ]
        self.delete_account(origin_account)

    @abimethod
    def check_expiration(self, account: Account) -> String:
        assert Txn.sender == account or Txn.sender == self.admin
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate."
        assert self.is_revoked[account] == UInt64(0), "The certificate is revoked."

        if Global.latest_timestamp > self.expiry_date[account]:
            validity = String("The certificate is expired.")
        else:
            validity = String("The certificate is not expired.")

        return validity

    @abimethod
    def check_revocation(self, account: Account) -> String:
        assert Txn.sender == self.admin or Txn.sender == account
        result, exists = self.certificateID.maybe(account)
        assert exists, "Account has not opted in."
        assert result, "This account does not have any certificate."
        assert (
            Global.latest_timestamp < self.expiry_date[account]
        ), "The certificate is caducated."

        if self.is_revoked[account] == UInt64(0):
            validity = String("The certificate is valid.")
        else:
            validity = String("The certificate is revoked.")

        return validity
