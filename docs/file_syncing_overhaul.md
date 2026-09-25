# File Syncing Overhaul Goals
- Offline support (storing a log of changes that happened while fsync was running).
- A more memory-efficient way to either receive a change and handle it or pass a async callback to handle the change.
- Avoid heavy abstractions or dependencies in the process.
- Improve error handling and logging.

## Bonus Goals (Possibly Design Changes needed Document throughly)
if you can find a way to do these and they actually do something useful, I would be very happy to see them implemented. 
Note I don't nesscerily know if doing something like this would improve the performance of fsync but I am open to it if your research says it will.

- Bonus: if you can find a more efficient way to handle different drives or file systems that would be pretty cool.
- Bonus: if you decide to use a FUSE filesystem, for efficiency I am not opposed but a FUSE system would be a lot more complicated.
It does make dertermining what change possible to move from the protocol layer to the filesystem layer which would be a major improvement but again introduces other issues.

I will let you if I change my mind on anything or have other ideas of what I need you to do here.
