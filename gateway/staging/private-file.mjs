import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import path from 'node:path';

function safeDirectoryAncestors(filename){
  let current=path.dirname(filename);
  while(true){
    const stat=lstatSync(current);
    if(!stat.isDirectory()||stat.isSymbolicLink()||
       (stat.mode&0o022)!==0&&!(stat.uid===0&&(stat.mode&0o1000)!==0)){
      throw new Error('Unsafe staging configuration directory');
    }
    const parent=path.dirname(current);
    if(parent===current)break;
    current=parent;
  }
}

export function readPrivateStagingFile(filename,{privateOnly=true}={}){
  if(typeof filename!=='string'||!path.isAbsolute(filename)||path.normalize(filename)!==filename)
    throw new TypeError('Staging file paths must be normalized absolute paths');
  safeDirectoryAncestors(filename);
  const before=lstatSync(filename);
  if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.uid!==process.getuid()||
     (before.mode&0o022)!==0||privateOnly&&(before.mode&0o077)!==0){
    throw new Error('Unsafe staging configuration file');
  }
  const fd=openSync(filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
  try{
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.dev!==before.dev||opened.ino!==before.ino||opened.uid!==before.uid||
       opened.nlink!==1||(opened.mode&0o022)!==0||privateOnly&&(opened.mode&0o077)!==0){
      throw new Error('Staging file changed while opening');
    }
    return readFileSync(fd);
  }finally{closeSync(fd);}
}
