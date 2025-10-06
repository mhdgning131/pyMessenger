from fpdf import FPDF
from fpdf.enums import XPos, YPos

# PDF title for the header
title = "Chasing Success"

class PDF(FPDF):
    def header(self):
        # Use DejaVu font
        self.set_font('DejaVu', 'B', 15)

        # Center title
        title_width = self.get_string_width(title) + 6
        doc_width = self.w
        self.set_x((doc_width - title_width) / 2)

        # Colors and border
        self.set_draw_color(0, 80, 180)
        self.set_fill_color(230, 230, 0)
        self.set_text_color(22, 50, 50)
        self.set_line_width(1)

        self.cell(title_width, 10, title, border=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C', fill=True)
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('DejaVu', 'I', 10)
        self.set_text_color(169, 169, 169)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

    def chapter_title(self, ch_title):
        self.set_font('DejaVu', 'B', 20)
        self.set_fill_color(200, 220, 255)
        title_text = f'Chapter: {ch_title}'
        self.cell(0, 10, title_text, fill=True, align='C')
        self.ln()

    def chapter_body(self, filename):
        # Read UTF-8 text
        with open(filename, 'r', encoding='utf-8') as f:
            text = f.read()

        self.set_font('DejaVu', '', 12)
        self.multi_cell(0, 5, text)
        self.ln()
        self.set_font('DejaVu', 'I', 12)
        self.cell(0, 5, "END OF CHAPTER", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def print_chapter(self, filename, ch_title):
        self.add_page()
        self.chapter_title(ch_title)
        self.chapter_body(filename)

# Create PDF
pdf = PDF('P', 'mm', 'Letter')

# meta data
pdf.set_title(title)
pdf.set_author('ME')

# link
website = "https://www.google.com"
ch_link = pdf.add_link()

# Register Unicode font
pdf.add_font('DejaVu', '', 'DejaVuSans.ttf')
pdf.add_font('DejaVu', 'B', 'DejaVuSans.ttf')
pdf.add_font('DejaVu', 'I', 'DejaVuSans.ttf')

# Enable auto page break
pdf.set_auto_page_break(auto=True, margin=15)

pdf.add_page()
pdf.image('wp2747979.jpg', x = -0.5, w = pdf.w + 1)

# Attach links
pdf.cell(0, 10, 'source', new_x=XPos.LMARGIN, new_y=YPos.NEXT, link=website)
# pdf.cell(0, 10, 'Chapter', new_x=XPos.LMARGIN, new_y=YPos.NEXT, link= ch_link)

# Chapters
pdf.print_chapter('succes.txt', "Rise, Even When It’s Hard")
pdf.print_chapter('do it.txt', "You Were Made for More")

# Output
pdf.output("test4.pdf")
print("PDF generated successfully as 'motivational_book.pdf'")

