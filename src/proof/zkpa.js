import zkpa from '../proof/zkpa.json';
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';

const backend = new BarretenbergBackend(zkpa);
const noir = new Noir(zkpa, backend);

// const input = imageData; 