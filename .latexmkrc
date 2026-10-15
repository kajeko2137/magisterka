# Sprawia, że zwykłe `latexmk` użyje XeLaTeX-a, a Biber uruchomi się sam
# (latexmk wykrywa biblatex po pliku .bcf).
$pdf_mode = 5;                 # 5 = xelatex
$bibtex_use = 2;               # 2 = zawsze uruchamiaj biber/bibtex
