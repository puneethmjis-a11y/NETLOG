// Seedable Mulberry32 random number generator for reproducibility
function mulberry32(a: number) {
  return function() {
    let t = a += 0x6D2B79F5;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class IsolationTreeNode {
  splitFeatureIndex: number = -1;
  splitValue: number = 0;
  leftChild: IsolationTreeNode | null = null;
  rightChild: IsolationTreeNode | null = null;
  size: number = 0;
  isLeaf: boolean = true;
}

export class IsolationForest {
  private numTrees: number;
  private subsampleSize: number;
  private trees: IsolationTreeNode[] = [];
  private datasetSize: number = 0;
  private random: () => number;

  constructor(numTrees = 100, subsampleSize = 256, seed = 42) {
    this.numTrees = numTrees;
    this.subsampleSize = subsampleSize;
    this.random = mulberry32(seed);
  }

  // Path length correction factor for BST of size n
  private c(n: number): number {
    if (n <= 1) return 0;
    if (n === 2) return 1;
    const eulerMascheroni = 0.5772156649;
    return 2 * (Math.log(n - 1) + eulerMascheroni) - (2 * (n - 1) / n);
  }

  public fit(data: number[][]): void {
    this.trees = [];
    this.datasetSize = data.length;
    if (this.datasetSize === 0) return;

    const actualSubsampleSize = Math.min(this.subsampleSize, this.datasetSize);

    for (let i = 0; i < this.numTrees; i++) {
      // Subsample data
      const subsample: number[][] = [];
      const indices = new Set<number>();
      while (indices.size < actualSubsampleSize) {
        const idx = Math.floor(this.random() * this.datasetSize);
        indices.add(idx);
      }
      for (const idx of indices) {
        subsample.push(data[idx]);
      }

      const maxDepth = Math.ceil(Math.log2(actualSubsampleSize));
      this.trees.push(this.buildTree(subsample, 0, maxDepth));
    }
  }

  private buildTree(data: number[][], currentDepth: number, maxDepth: number): IsolationTreeNode {
    const node = new IsolationTreeNode();
    node.size = data.length;

    if (currentDepth >= maxDepth || data.length <= 1) {
      node.isLeaf = true;
      return node;
    }

    // Find valid features (features that have some variance in this subset)
    const numFeatures = data[0].length;
    const validFeatures: number[] = [];
    const minMaxMap = new Map<number, { min: number; max: number }>();

    for (let f = 0; f < numFeatures; f++) {
      let min = data[0][f];
      let max = data[0][f];
      for (let i = 1; i < data.length; i++) {
        if (data[i][f] < min) min = data[i][f];
        if (data[i][f] > max) max = data[i][f];
      }
      if (max > min) {
        validFeatures.push(f);
        minMaxMap.set(f, { min, max });
      }
    }

    // If all features are identical, stop
    if (validFeatures.length === 0) {
      node.isLeaf = true;
      return node;
    }

    // Pick a random feature from valid ones
    const fIdx = validFeatures[Math.floor(this.random() * validFeatures.length)];
    const bounds = minMaxMap.get(fIdx)!;

    // Pick a random split value between min and max
    const splitVal = bounds.min + this.random() * (bounds.max - bounds.min);

    node.splitFeatureIndex = fIdx;
    node.splitValue = splitVal;
    node.isLeaf = false;

    // Partition
    const leftData: number[][] = [];
    const rightData: number[][] = [];
    for (const point of data) {
      if (point[fIdx] < splitVal) {
        leftData.push(point);
      } else {
        rightData.push(point);
      }
    }

    node.leftChild = this.buildTree(leftData, currentDepth + 1, maxDepth);
    node.rightChild = this.buildTree(rightData, currentDepth + 1, maxDepth);

    return node;
  }

  public computePathLength(x: number[], node: IsolationTreeNode, currentDepth: number): number {
    if (node.isLeaf) {
      return currentDepth + this.c(node.size);
    }

    const fIdx = node.splitFeatureIndex;
    if (x[fIdx] < node.splitValue) {
      return this.computePathLength(x, node.leftChild!, currentDepth + 1);
    } else {
      return this.computePathLength(x, node.rightChild!, currentDepth + 1);
    }
  }

  public predictScore(x: number[]): number {
    if (this.trees.length === 0) return 0.5;

    let pathLengthSum = 0;
    for (const tree of this.trees) {
      pathLengthSum += this.computePathLength(x, tree, 0);
    }
    const avgPathLength = pathLengthSum / this.trees.length;

    const n = Math.min(this.subsampleSize, this.datasetSize);
    const cVal = this.c(n);
    if (cVal === 0) return 0.5;

    // anomaly score s(x, n) = 2^(- E(h(x)) / c(n))
    return Math.pow(2, -(avgPathLength / cVal));
  }
}
