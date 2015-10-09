# Set this to one or more main LaTeX files (e.g. those with \documentclass) 
# for a specific build. Leave blank to build all files having an uncommented
# \documentclass.
MAIN=paper.tex


###########################################################################
#                 MAKE NO EDITS BELOW (except to debug)                   #
###########################################################################
#
# Makefile
# By Jonathon Giffin
#
# This is the PDFLATEX makefile, no support for ps/eps/dvi.
#
# Originally based on 
#   http://www.acoustics.hut.fi/u/mairas/UltimateLatexMakefile/Makefile
# but redeveloped by JG. Reuse by changing just the first line to list
# the main LaTeX source file.
#
# Features:
# - Finds all included LaTeX files, including includes within includes.
# - Finds all bibs and PDF figures included.
# - Automatically generates dependency information.
# - Repeats calls to PDFLATEX as necessary to fix cross references.
# - Displays missing references in a clean format at the end of the build.
# - Finds main LaTeX source files, so this makefile is reusable wihtout edits.
# - Works for files with bibliographies, and files without.

ifndef MAIN
MAIN:=	$(shell egrep -l "^[^%]*\documentclass" *.tex)	
endif

ALLTEX:=$(shell ls *.tex)
ALLPDF:=$(ALLTEX:.tex=.pdf)

all pdf: $(MAIN:.tex=.pdf)
help ps dvi $(MAIN:.tex=.ps) $(MAIN:.tex=.dvi): die_unsupported
$(filter-out $(MAIN:.tex=.pdf),$(ALLPDF)): die_unsupported

%.pdf: %.fig
	rm -f $@
	fig2dev -L pdf $< > $@

%.aux: %.tex
	$(LATEX) $<

%.bbl: %.tex biblio.bib
	bibtex $(<:.tex=)
	$(LATEX) $<

%.pdf: %.aux
	@while (grep -q "Rerun to get" $(<:.aux=.log)) do \
		$(LATEX) $(<:.aux=.tex); \
	done
	@egrep -i "(Reference|Citation).*undefined" $(<:.aux=.log) ; true

%.dep: %.tex
	@$(gettexs); $(getbibs); $(getfigs); \
	echo "$(<:.tex=.dep): Makefile " $$texs $$bibs $$figs > $@; \
	echo "$(<:.tex=.aux): " $$texs $$figs >> $@; \
	if [ $${#bibs} -gt 0 ]; then \
		echo "$(<:.tex=.bbl): " $$texs $$bibs >> $@; \
		echo "$(<:.tex=.pdf): $(<:.tex=.bbl)" >> $@; \
	fi

vpath %.fig figs

-include $(MAIN:.tex=.dep)

.PHONY: clean die_unsupported

double:
	for i in $(ALLTEX); do echo "Double words in $$i:" && ./double.pl < $$i; done

clean:
	rm -f *~ *.log *.aux *.dvi *.bbl *.blg *.cb *.dep *-diff.tex $(TARGET)

die_unsupported:
	$(warning Unsupported Makefile build target. Supported targets are:)
	$(warning  <BLANK> all pdf $(TARGET) clean)
	$(error Exiting)

LATEX=	xelatex #--interaction batchmode
TARGET=	$(MAIN:.tex=.pdf)

# 9 Dec 2008 JG: This is now a worklist algorithm to pick up all recursive
#   child dependencies of discovered includes.
define gettexs
  worklist="$< "; \
  while [ $${#worklist} -gt 0 ]; do \
    curr=$${worklist%% *}; \
    worklist=$${worklist#* }; \
    texs="$${texs}$$curr "; \
    worklist=$${worklist}`perl -ne '\
               ($$_)=/^[^%]*\\\(?:include|input)\{(.*?)\}/; \
	       @_=split /,/; \
	       foreach $$t (@_) { \
	         if ($$t !~ /\.tex$$/) { $$t .= ".tex"; } \
                 if (-e $$t) { print "$$t " } \
	       }' $${curr}`; \
	done
endef

define getbibs
  bibs=`perl -ne '\
        ($$_)=/^[^%]*\\\bibliography\{(.*?)\}/; \
        @_=split /,/; \
        foreach $$b (@_) { \
          if (-e "$$b.bib") { print "$$b.bib " } \
        }' $$texs`
endef

define getfigs
  figs=`perl -ne '\
        ($$_)=/^[^%]*\\\includegraphics(?:\[.*?\])?\{(.*?)\}/g; \
        if (defined($$_)) { \
          if ($$_ !~ /\.pdf$$/) { $$_ .= ".pdf"; } \
          if (-e $$_) { print "$$_ "; } \
        }' $$texs`
endef
