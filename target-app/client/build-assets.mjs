import { copyFileSync, mkdirSync } from 'node:fs';
mkdirSync('assets', { recursive: true });
copyFileSync('node_modules/@fontsource/material-symbols-outlined/files/material-symbols-outlined-latin-400-normal.woff2', 'assets/icons.woff2');
copyFileSync('node_modules/@fontsource/material-symbols-outlined/LICENSE', 'assets/icons-LICENSE.txt');
