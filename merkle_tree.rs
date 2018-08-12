use sha3::{Digest, Sha3_256};


#[derive(Clone)]
struct Node {
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
    hash: Vec<u8>,
}


impl Node {
    fn new_leaf(hash: Vec<u8>) -> Self {
        Self {
            left: None,
            right: None,
            hash: hash,
        }
    }

    fn new_internal(hash: Vec<u8>, left: Box<Node>, right: Box<Node>) -> Self {
        Self {
            left: Some(left),
            right: Some(right),
            hash: hash,
        }
    }
}

struct MerkleTree {
    root: Node,
    size: usize,
}


fn _sha3(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::default();
    hasher.input(input);

    let mut res = Vec::new();
    for x in hasher.result() {
        res.push(x);
    }

    res
}

fn _sha3_leaves(leaf_hash_1: &[u8], leaf_hash_2: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::default();
    hasher.input(leaf_hash_1);
    hasher.input(leaf_hash_2);

    let mut res = Vec::new();
    for x in hasher.result() {
        res.push(x);
    }

    res
}


impl MerkleTree {
    fn build(items: Vec<&[u8]>) -> Self {
        let leaves: Vec<Box<Node>> = items
            .into_iter()
            .map(|leaf_data| _sha3(leaf_data))
            .map(|hash| Box::new(Node::new_leaf(hash)))
            .collect();

        let size = leaves.len();
        let root = Self::_build_up(leaves)[0].clone();

        Self {
            root: *root,
            size: size,
        }
    }

    fn _build_up(mut nodes: Vec<Box<Node>>) -> Vec<Box<Node>> {
        let node_count = nodes.len();
        if node_count == 1 { return nodes }

        if node_count % 2 == 1 {
            let duplicate = nodes[node_count - 1].clone();
            nodes.push(duplicate);
        }

        let mut parents = Vec::new();
        let mut i = 0;
        while i < nodes.len() {
            let left_child = nodes[i].clone();
            let right_child = nodes[i + 1].clone();
            let combined_hash = _sha3_leaves(&left_child.hash, &right_child.hash);
            let parent_node = Box::new(Node::new_internal(combined_hash, left_child, right_child));
            parents.push(parent_node);
            i += 2;
        }

        return Self::_build_up(parents);
    }

    fn get_root_hash(&self) -> &[u8] {
        &self.root.hash
    }

    fn get_proof(&self, index: usize) -> Option<Vec<Vec<u8>>> {
        if index >= self.size { return None }

        let level_size = 2f64.powf((self.size as f64).log2().ceil()) as usize;
        let mut position = level_size + index;
        let mut directions = Vec::new();

        while position >= 2 {
            let direction = position % 2;
            position = position / 2;
            directions.push(direction);
        }

        for i in 0 .. directions.len() / 2 {
            let opposite = directions.len() - i - 1;
            let tmp = directions[i];
            directions[i] = directions[opposite];
            directions[opposite] = tmp;
        }
        println!("Directions: {:?}", directions);

        let mut path = Vec::new();
        let mut node = &self.root;

        for direction in directions {
            if direction == 1 {
                let mut hash = node.left.as_ref().unwrap().hash.to_owned();
                hash.push('l' as u8);
                path.push(hash);
                node = &node.right.as_ref().unwrap();
            } else {
                let mut hash = node.right.as_ref().unwrap().hash.to_owned();
                hash.push('r' as u8);
                path.push(hash);
                node = &node.left.as_ref().unwrap();
            }
        }

        for i in 0 .. path.len() / 2 {
            let opposite_index = path.len() - i - 1;
            path.swap(i, opposite_index);
        }

        Some(path)
    }
}


#[cfg(test)]
mod tests {
    use sha3::Sha3_256;

    use super::{MerkleTree, _sha3};


    #[test]
    fn test_hash() {
        assert_eq!(&_sha3(&vec![1,2,3]), &b"\xfd\x17\x80\xa6\xfc\x9e\xe0\xda\xb2l\xebK9A\xab\x03\xe6l\xcd\x97\r\x1d\xb9\x16\x12\xc6m\xf4Q[\n\n");
    }


    #[test]
    fn test_building() {
        let items: Vec<Vec<u8>> = vec![vec![1,2,3], vec![4,5,6], vec![7,8,9]];
        let input = items.iter().map(|x| x.as_ref()).collect();

        let merkle_tree = MerkleTree::build(input);

        assert_eq!(merkle_tree.size, 3);
        assert_eq!(&merkle_tree.get_root_hash(), &b"\xbe\xa3\xfd\xa3\xa0\xb8=%\xef\xf3\xd4\x1cj\xa2\xd6=\x03I,\xcc0\xda\x1dg\x8a\x08o\x81g%1d");
    }

    #[test]
    fn test_proof() {
        let items: Vec<Vec<u8>> = vec![vec![1,2,3], vec![4,5,6], vec![7,8,9]];
        let input = items.iter().map(|x| x.as_ref()).collect();
        let path_item_1: Vec<u8> = b"\xfd\x17\x80\xa6\xfc\x9e\xe0\xda\xb2l\xebK9A\xab\x03\xe6l\xcd\x97\r\x1d\xb9\x16\x12\xc6m\xf4Q[\n\nl".to_vec();
        let path_item_2: Vec<u8> = b")\xf0\xb7]\x17K\xd38D.z\xca|X{0a\x8a\xe6\xa7\x03\x1e\xbeT\xb8:\xd1&\x8faK\xa2r".to_vec();
        let expected_proof = vec![path_item_1, path_item_2];

        let merkle_tree = MerkleTree::build(input);
        let proof = merkle_tree.get_proof(1).unwrap();

        for (i, expected_hash) in expected_proof.iter().enumerate() {
            let actual_hash = &proof[i];
            println!("Expected: {:?}. Actual: {:?}", expected_hash, actual_hash);
            assert_eq!(actual_hash, expected_hash);
        }
    }
}