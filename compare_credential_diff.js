export function findDifferences(original, uploaded) {
  const added = {};
  const removed = {};
  const changed = {};

  for (const key in uploaded) {
    if (!(key in original)) {
      added[key] = uploaded[key];
    } else if (JSON.stringify(uploaded[key]) !== JSON.stringify(original[key])) {
      changed[key] = {
        from: original[key],
        to: uploaded[key]
      };
    }
  }

  for (const key in original) {
    if (!(key in uploaded)) {
      removed[key] = original[key];
    }
  }

  return { added, removed, changed };
}
