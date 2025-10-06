from fpdf import FPDF
from fpdf.enums import XPos, YPos

class PDF(FPDF):
    # page header
    def header(self):
        # logo
        self.image('R.png', 10, 8, 25)
        # font
        self.set_font('helvetica', 'B', 20)
        # padding
        self.cell(80)
        # title
        self.cell(30, 10, 'Title', True, new_x= XPos.LMARGIN, new_y= YPos.NEXT, align='C')
        # line break
        self.ln(20)

    # page footer
    def footer(self):
        # set position of the footer
        self.set_y(-15)
        self.set_font('helvetica', 'I', 10)
        # page number
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')

# create FPDF object
pdf = PDF('P', 'mm', 'Letter')

# set auto page break
pdf.set_auto_page_break(True, 15)

# add page a page
pdf.add_page()

# specify font
pdf.set_font('helvetica', 'BUI', 16)

pdf.set_font('helvetica', '', 12)

for i in range(1, 41):
    pdf.cell(0, 10, f'This is line {i}:D', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
# add text
pdf.cell(80, 10, "goodbye")

pdf.output("test2.pdf")
