package repository

import (
	entsql "entgo.io/ent/dialect/sql"
	dbpredicate "github.com/jk-zhang-meta/berth/ent/predicate"
)

// Owned accounts must never enter the legacy ungrouped public pool, including
// the interval between account creation and private-group provisioning.
func withoutPrivateStewards() dbpredicate.Account {
	return func(s *entsql.Selector) {
		s.Where(entsql.ExprP("NOT EXISTS (SELECT 1 FROM account_stewards st JOIN users u ON u.id=st.user_id WHERE st.account_id=" + s.C("id") + " AND u.role <> 'admin')"))
	}
}

// A managed private binding does not remove administrator resources from their
// pre-existing legacy ungrouped pool. Ordinary user resources are excluded above.
func withoutPublicGroupBindings() dbpredicate.Account {
	return func(s *entsql.Selector) {
		s.Where(entsql.ExprP("NOT EXISTS (SELECT 1 FROM account_groups ag LEFT JOIN berth_account_groups bg ON bg.group_id=ag.group_id WHERE ag.account_id=" + s.C("id") + " AND bg.group_id IS NULL)"))
	}
}
