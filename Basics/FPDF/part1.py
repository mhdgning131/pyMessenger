from fpdf import FPDF
from fpdf.enums import XPos, YPos

# create FPDF object
""" We can specify:
    the orientation('P' or 'L')
    the unit('mm', 'cm' or 'in')
    the format('A3', 'A4'(default), 'A5', 'Letter', 'Legal' or (100, 150))"""
pdf = FPDF('P', 'mm', 'A4')

# add page a page
pdf.add_page()

# specify font
""" fonts('times', 'courier', 'helvetica', symbol', 'zapfdingbats')
    style('B' (bold), 'U' (underline), 'I' (italics), '' (regular), combination (i.e, ('BU')))
    Size is in points, not millimeters"""
pdf.set_font('helvetica', '', 11)

# add text
""" We can specify:
    w = width
    h = height
    border = 0 (no frame) or 1 (framed)
    align('L', 'C' or 'R')
    new_x, new_y: controls next position"""
pdf.cell(120, 10, "Hello World", new_x=XPos.LMARGIN, new_y=YPos.NEXT, border= 0, align='C')

pdf.cell(80, 10, "goodbye")

pdf.output("test1.pdf")
