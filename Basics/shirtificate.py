from fpdf import FPDF

def main():
    name = input("Name: ")
    shirt_pdf(name)

def shirt_pdf(name):
    pdf = FPDF(orientation='P', unit='mm', format='A4')

    pdf.add_page()
    pdf.set_font('helvetica', '', 50)
    pdf.cell(w=0, h=50, text='CS50 Shirtificate', align='C')
    pdf.ln(50)

    pdf.set_font('helvetica', '', 25)
    pdf.set_text_color(255, 255, 255)

    pdf.image('shirtificate.png', x=10, y=70, w=190)
    pdf.cell(w=0, h=150, text=f'{name} took CS50', align='C')

    pdf.output('shirtificate.pdf')

if __name__ == '__main__':
    main()