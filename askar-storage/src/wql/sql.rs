use std::marker::PhantomData;

use itertools::Itertools;

use super::tags::{CompareOp, ConjunctionOp, TagName, TagQueryEncoder};
use crate::error::Error;

/// The maximum number of terms in one compound `UNION ALL` select.
///
/// SQLite rejects a compound SELECT with more than 500 terms
/// (`SQLITE_MAX_COMPOUND_SELECT`). The limit applies to each compound select,
/// so a larger union is split into nested groups.
const MAX_UNION_TERMS: usize = 400;

/// An encoded tag filter clause
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagSqlClause {
    /// The condition on the item `i`
    pub condition: String,
    /// The subqueries that select the IDs of the matching items, if the clause
    /// has a positive tag match to start from. The union of the subqueries
    /// selects the items of the clause.
    pub item_ids: Option<Vec<String>>,
    /// The number of positive tag matches in the clause
    pub tag_matches: usize,
}

impl TagSqlClause {
    fn tag_match(subquery: String, negate: bool) -> Self {
        if negate {
            Self {
                condition: format!("i.id NOT IN ({})", subquery),
                item_ids: None,
                tag_matches: 0,
            }
        } else {
            Self {
                condition: format!("i.id IN ({})", subquery),
                item_ids: Some(vec![subquery]),
                tag_matches: 1,
            }
        }
    }
}

/// Join the subqueries with `UNION ALL`.
///
/// Each compound select gets at most `MAX_UNION_TERMS` terms. A larger union
/// is split into groups, and each group is a subquery in the outer union.
fn union_sql(terms: &[String]) -> String {
    if terms.len() <= MAX_UNION_TERMS {
        return Itertools::intersperse(terms.iter().map(String::as_str), " UNION ALL ")
            .collect::<String>();
    }
    let groups = terms
        .chunks(MAX_UNION_TERMS)
        .map(|group| format!("SELECT * FROM ({}) AS u", union_sql(group)))
        .collect::<Vec<_>>();
    union_sql(&groups)
}

pub struct TagSqlEncoder<'e, EN, EV> {
    pub enc_name: EN,
    pub enc_value: EV,
    pub arguments: Vec<Vec<u8>>,
    _pd: PhantomData<&'e ()>,
}

impl<'e, EN, EV> TagSqlEncoder<'e, EN, EV>
where
    EN: Fn(&str) -> Result<Vec<u8>, Error> + 'e,
    EV: Fn(&str) -> Result<Vec<u8>, Error> + 'e,
{
    pub fn new(enc_name: EN, enc_value: EV) -> Self {
        Self {
            enc_name,
            enc_value,
            arguments: vec![],
            _pd: PhantomData,
        }
    }
}

impl<'e, EN, EV> TagQueryEncoder for TagSqlEncoder<'e, EN, EV>
where
    EN: Fn(&str) -> Result<Vec<u8>, Error> + 'e,
    EV: Fn(&str) -> Result<Vec<u8>, Error> + 'e,
{
    type Arg = Vec<u8>;
    type Clause = TagSqlClause;

    fn encode_name(&mut self, name: &TagName) -> Result<Self::Arg, Error> {
        Ok(match name {
            TagName::Encrypted(name) | TagName::Plaintext(name) => (self.enc_name)(name)?,
        })
    }

    fn encode_value(&mut self, value: &str, is_plaintext: bool) -> Result<Self::Arg, Error> {
        Ok(if is_plaintext {
            value.as_bytes().to_vec()
        } else {
            (self.enc_value)(value)?
        })
    }

    fn encode_op_clause(
        &mut self,
        op: CompareOp,
        enc_name: Self::Arg,
        enc_value: Self::Arg,
        is_plaintext: bool,
        negate: bool,
    ) -> Result<Option<Self::Clause>, Error> {
        let idx = self.arguments.len();
        let (op_prefix, match_prefix) = match (is_plaintext, op.as_sql_str_for_prefix()) {
            (false, Some(pfx_op)) if enc_value.len() > 12 => {
                // the first 12 characters of an encrypted tag is the nonce, based
                // on an HMAC of the rest of the value. it serves as an effective index
                // on its own
                let match_prefix = enc_value[..12].to_vec();
                (
                    format!(" AND SUBSTR(value, 1, 12) {} ${}", pfx_op, idx + 3),
                    Some(match_prefix),
                )
            }
            _ => (String::new(), None),
        };
        self.arguments.push(enc_name);
        self.arguments.push(enc_value);
        if let Some(v) = match_prefix {
            self.arguments.push(v);
        }

        let query = format!(
            "SELECT item_id FROM items_tags WHERE name = ${} AND value {} ${}{} AND plaintext = {}",
            idx + 1,
            op.as_sql_str(),
            idx + 2,
            op_prefix.as_str(),
            i32::from(is_plaintext)
        );
        Ok(Some(TagSqlClause::tag_match(query, negate)))
    }

    fn encode_in_clause(
        &mut self,
        enc_name: Self::Arg,
        enc_values: Vec<Self::Arg>,
        is_plaintext: bool,
        negate: bool,
    ) -> Result<Option<Self::Clause>, Error> {
        let args_in = Itertools::intersperse(std::iter::repeat_n("$$", enc_values.len()), ", ")
            .collect::<String>();
        let query = format!(
            "SELECT item_id FROM items_tags WHERE name = $$ AND value IN ({}) AND plaintext = {}",
            args_in,
            i32::from(is_plaintext)
        );
        self.arguments.push(enc_name);
        self.arguments.extend(enc_values);
        Ok(Some(TagSqlClause::tag_match(query, negate)))
    }

    fn encode_exist_clause(
        &mut self,
        enc_name: Self::Arg,
        is_plaintext: bool,
        negate: bool,
    ) -> Result<Option<Self::Clause>, Error> {
        let query = format!(
            "SELECT item_id FROM items_tags WHERE name = $$ AND plaintext = {}",
            i32::from(is_plaintext)
        );
        self.arguments.push(enc_name);
        Ok(Some(TagSqlClause::tag_match(query, negate)))
    }

    fn encode_conj_clause(
        &mut self,
        op: ConjunctionOp,
        clauses: Vec<Self::Clause>,
    ) -> Result<Option<Self::Clause>, Error> {
        let qc = clauses.len();
        if qc == 0 {
            if op == ConjunctionOp::Or {
                return Ok(Some(TagSqlClause {
                    condition: "0".to_string(),
                    item_ids: None,
                    tag_matches: 0,
                }));
            } else {
                return Ok(None);
            }
        }
        if qc == 1 {
            return Ok(clauses.into_iter().next());
        }
        let tag_matches = clauses.iter().map(|c| c.tag_matches).sum::<usize>();

        // The planner cannot use the tag indexes for subqueries joined by OR, and
        // scans all items instead. If each OR branch has a positive tag match, select
        // the union of the matching item IDs in one subquery, which the planner can
        // start from.
        if op == ConjunctionOp::Or && clauses.iter().all(|c| c.item_ids.is_some()) {
            let item_ids = clauses
                .into_iter()
                .flat_map(|c| c.item_ids.unwrap_or_default())
                .collect::<Vec<_>>();
            return Ok(Some(TagSqlClause {
                condition: format!("i.id IN ({})", union_sql(&item_ids)),
                item_ids: Some(item_ids),
                tag_matches,
            }));
        }

        let condition = format!(
            "({})",
            Itertools::intersperse(
                clauses.iter().map(|c| c.condition.as_str()),
                op.as_sql_str()
            )
            .collect::<String>()
        );
        // An AND clause with a positive tag match can select its items without a scan.
        // The alias `i` in the subquery hides the outer `i`, so that the conditions
        // apply to the items of the subquery.
        let item_ids = (op == ConjunctionOp::And && clauses.iter().any(|c| c.item_ids.is_some()))
            .then(|| vec![format!("SELECT i.id FROM items i WHERE {}", condition)]);
        Ok(Some(TagSqlClause {
            condition,
            item_ids,
            tag_matches,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tags::TagQuery;
    use super::*;

    fn encode(query: &TagQuery) -> String {
        let mut enc = TagSqlEncoder::new(
            |name: &str| Ok(format!("--{}--", name).into_bytes()),
            |value: &str| Ok(value.to_uppercase().into_bytes()),
        );
        enc.encode_query(query).unwrap().unwrap().condition
    }

    fn plain_eq(name: &str, value: &str) -> TagQuery {
        TagQuery::Eq(TagName::Plaintext(name.to_string()), value.to_string())
    }

    #[test]
    fn tag_query_encode_and() {
        let query = TagQuery::And(vec![plain_eq("a", "1"), plain_eq("b", "2")]);
        assert_eq!(encode(&query), "(i.id IN (SELECT item_id FROM items_tags WHERE name = $1 AND value = $2 AND plaintext = 1) AND i.id IN (SELECT item_id FROM items_tags WHERE name = $3 AND value = $4 AND plaintext = 1))");
    }

    #[test]
    fn tag_query_encode_or_nested() {
        let query = TagQuery::Or(vec![
            plain_eq("a", "1"),
            TagQuery::Or(vec![plain_eq("b", "2"), plain_eq("c", "3")]),
        ]);
        assert_eq!(encode(&query), "i.id IN (SELECT item_id FROM items_tags WHERE name = $1 AND value = $2 AND plaintext = 1 UNION ALL SELECT item_id FROM items_tags WHERE name = $3 AND value = $4 AND plaintext = 1 UNION ALL SELECT item_id FROM items_tags WHERE name = $5 AND value = $6 AND plaintext = 1)");
    }

    #[test]
    fn tag_query_encode_or_above_union_limit() {
        // An OR with more terms than one compound SELECT accepts is split into
        // nested groups. The terms of a nested OR are part of the same union.
        let many = (0..MAX_UNION_TERMS)
            .map(|idx| plain_eq("a", &idx.to_string()))
            .collect::<Vec<_>>();
        let query = TagQuery::Or(vec![TagQuery::Or(many), plain_eq("b", "2")]);
        let encoded = encode(&query);
        assert!(encoded.starts_with("i.id IN (SELECT * FROM (SELECT item_id FROM items_tags WHERE name = $1 AND value = $2 AND plaintext = 1 UNION ALL SELECT item_id"));
        assert!(encoded.ends_with(&format!(
            " AND plaintext = 1) AS u UNION ALL SELECT * FROM (SELECT item_id FROM items_tags WHERE name = ${} AND value = ${} AND plaintext = 1) AS u)",
            MAX_UNION_TERMS * 2 + 1,
            MAX_UNION_TERMS * 2 + 2
        )));
        assert_eq!(encoded.matches(" UNION ALL ").count(), MAX_UNION_TERMS);
        assert_eq!(encoded.matches("SELECT * FROM (").count(), 2);
    }

    #[test]
    fn tag_query_encode_or_without_positive_match() {
        // A branch without a positive tag match can not select its items without
        // a scan, so the OR is kept as a condition on the items
        let query = TagQuery::Or(vec![
            plain_eq("a", "1"),
            TagQuery::Not(Box::new(plain_eq("b", "2"))),
        ]);
        assert_eq!(encode(&query), "(i.id IN (SELECT item_id FROM items_tags WHERE name = $1 AND value = $2 AND plaintext = 1) OR i.id NOT IN (SELECT item_id FROM items_tags WHERE name = $3 AND value = $4 AND plaintext = 1))");
    }

    #[test]
    fn tag_query_encode_not_or() {
        // NOT (a OR b) is encoded as (NOT a AND NOT b)
        let query = TagQuery::Not(Box::new(TagQuery::Or(vec![
            plain_eq("a", "1"),
            plain_eq("b", "2"),
        ])));
        assert_eq!(encode(&query), "(i.id NOT IN (SELECT item_id FROM items_tags WHERE name = $1 AND value = $2 AND plaintext = 1) AND i.id NOT IN (SELECT item_id FROM items_tags WHERE name = $3 AND value = $4 AND plaintext = 1))");
    }

    #[test]
    fn tag_query_encode() {
        let condition_1 = TagQuery::And(vec![
            TagQuery::Eq(
                TagName::Encrypted("enctag".to_string()),
                "noncenonce12encval".to_string(),
            ),
            TagQuery::Eq(
                TagName::Plaintext("plaintag".to_string()),
                "plainval".to_string(),
            ),
        ]);
        let condition_2 = TagQuery::And(vec![
            TagQuery::Eq(
                TagName::Encrypted("enctag".to_string()),
                "noncenonce12encval".to_string(),
            ),
            TagQuery::Not(Box::new(TagQuery::Eq(
                TagName::Plaintext("plaintag".to_string()),
                "eggs".to_string(),
            ))),
        ]);
        let query = TagQuery::Or(vec![condition_1, condition_2]);
        let mut enc = TagSqlEncoder::new(
            |name: &str| Ok(format!("--{}--", name).into_bytes()),
            |value: &str| Ok(value.to_uppercase().into_bytes()),
        );
        let query_str = enc.encode_query(&query).unwrap().unwrap().condition;
        assert_eq!(query_str, "i.id IN (SELECT i.id FROM items i WHERE (i.id IN (SELECT item_id FROM items_tags WHERE name = $1 AND value = $2 AND SUBSTR(value, 1, 12) = $3 AND plaintext = 0) AND i.id IN (SELECT item_id FROM items_tags WHERE name = $4 AND value = $5 AND plaintext = 1)) UNION ALL SELECT i.id FROM items i WHERE (i.id IN (SELECT item_id FROM items_tags WHERE name = $6 AND value = $7 AND SUBSTR(value, 1, 12) = $8 AND plaintext = 0) AND i.id NOT IN (SELECT item_id FROM items_tags WHERE name = $9 AND value = $10 AND plaintext = 1)))");
        let args = enc.arguments;
        assert_eq!(
            args,
            vec![
                b"--enctag--".to_vec(),
                b"NONCENONCE12ENCVAL".to_vec(),
                b"NONCENONCE12".to_vec(),
                b"--plaintag--".to_vec(),
                b"plainval".to_vec(),
                b"--enctag--".to_vec(),
                b"NONCENONCE12ENCVAL".to_vec(),
                b"NONCENONCE12".to_vec(),
                b"--plaintag--".to_vec(),
                b"eggs".to_vec()
            ]
        );
    }
}
