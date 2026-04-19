use aegis_model::ProcessContext;
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessNode {
    pub context: ProcessContext,
    pub children: BTreeSet<(u32, u64)>,
    pub last_activity_ns: u64,
}

#[derive(Default)]
pub struct ProcessTree {
    nodes: HashMap<(u32, u64), ProcessNode>,
}

impl ProcessTree {
    pub fn on_process_create(&mut self, context: ProcessContext, timestamp_ns: u64) {
        let key = (context.pid, context.start_time_ns);
        let parent_key = (context.ppid, 0);
        let node = ProcessNode {
            context: context.clone(),
            children: BTreeSet::new(),
            last_activity_ns: timestamp_ns,
        };
        self.nodes.insert(key, node);

        if let Some(parent) = self
            .nodes
            .iter_mut()
            .find(|((pid, _start_time), _)| *pid == parent_key.0)
            .map(|(_, node)| node)
        {
            parent.children.insert(key);
        }
    }

    pub fn on_process_exit(&mut self, pid: u32, start_time_ns: u64) -> Option<ProcessNode> {
        let key = (pid, start_time_ns);
        let removed = self.nodes.remove(&key)?;
        for parent in self.nodes.values_mut() {
            parent.children.remove(&key);
        }
        Some(removed)
    }

    pub fn touch(&mut self, pid: u32, start_time_ns: u64, timestamp_ns: u64) {
        if let Some(node) = self.nodes.get_mut(&(pid, start_time_ns)) {
            node.last_activity_ns = timestamp_ns;
        }
    }

    pub fn get_ancestor_chain(&self, pid: u32, start_time_ns: u64) -> Vec<ProcessContext> {
        let mut chain = Vec::new();
        let mut current = (pid, start_time_ns);

        while let Some(node) = self.nodes.get(&current) {
            chain.push(node.context.clone());
            if node.context.ppid == 0 {
                break;
            }
            let next = self
                .nodes
                .keys()
                .find(|(candidate_pid, _)| *candidate_pid == node.context.ppid)
                .copied();
            match next {
                Some(parent) => current = parent,
                None => break,
            }
        }

        chain
    }

    pub fn is_descendant_of(&self, pid: u32, start_time_ns: u64, ancestor_pid: u32) -> bool {
        self.get_ancestor_chain(pid, start_time_ns)
            .iter()
            .skip(1)
            .any(|context| context.pid == ancestor_pid)
    }

    pub fn snapshot(&self) -> Vec<ProcessContext> {
        self.nodes
            .values()
            .map(|node| node.context.clone())
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessTree;
    use aegis_model::ProcessContext;

    #[test]
    fn tracks_parent_child_relationships() {
        let mut tree = ProcessTree::default();
        tree.on_process_create(
            ProcessContext {
                pid: 10,
                ppid: 0,
                start_time_ns: 1,
                name: "parent".to_string(),
                ..ProcessContext::default()
            },
            1,
        );
        tree.on_process_create(
            ProcessContext {
                pid: 11,
                ppid: 10,
                start_time_ns: 2,
                name: "child".to_string(),
                ..ProcessContext::default()
            },
            2,
        );

        assert!(tree.is_descendant_of(11, 2, 10));
        assert_eq!(tree.get_ancestor_chain(11, 2).len(), 2);
    }
}
