# myapp.py

from random import random

from bokeh.layouts import column
from bokeh.models import Button
from bokeh.palettes import RdYlBu3
from bokeh.plotting import figure, curdoc
from bokeh.models import ColumnDataSource

# create a plot and style its properties
p = figure(x_range=(0, 100), y_range=(0, 100), toolbar_location=None)
p.border_fill_color = 'black'
p.background_fill_color = 'black'
p.outline_line_color = None
p.grid.grid_line_color = None

# add a text renderer to the plot (no data yet)
r = p.text(x=[], y=[], text=[], text_color=[], text_font_size="26px",
           text_baseline="middle", text_align="center")

i = 0

ds = r.data_source

# create a callback that adds a number in a random location
def callback():
    global i

    # BEST PRACTICE --- update .data in one step with a new dict
    new_data = dict()
    new_data['x'] = ds.data['x'] + [random()*70 + 15]
    new_data['y'] = ds.data['y'] + [random()*70 + 15]
    new_data['text_color'] = ds.data['text_color'] + [RdYlBu3[i%3]]
    new_data['text'] = ds.data['text'] + [str(i)]
    ds.data = new_data

    i = i + 1

# add a button widget and configure with the call back
button = Button(label="Press Me")
button.on_click(callback)


import pandas as pd

df_dd = pd.read_csv('./data/2022-03-08 03:25:32.csv')
f = figure()
source = ColumnDataSource(df_comb)

s = f.hbar(x='index', bottom=0, top='S_w', width=0.5, source=source)
p1 = f.hbar(x='index', bottom='S_w', top=1, width=0.5, source=source, color='orange')

s_label = f.text(x='index', y='S_w_labelheights', source=source, text='S')
p_label = f.text(x='index', y='P_w_labelheights', source=source, text='P')


# put the button and plot in a layout and add to the document
curdoc().add_root(column(button, p))
curdoc().add_root(column(button, p))