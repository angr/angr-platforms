set PATH=Z:\;C:\msc510\bin;C:\msc510\binb;C:\msc510\bound;C:\msc510
set INCLUDE=C:\msc510\include
set LIB=C:\msc510\lib
mount d x16_samples
mount e x16_samples
mount c "dos/msc510/bin/../"
d:
cl /Fc /Zi /Od /AT /FeITOD.COM IDEMO.C > COMTEST.LOG
