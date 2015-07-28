import json

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.project import __project__
from viper.common.utils import get_viper_path

try:
    import numpy
    HAVE_NUMPY = True
except ImportError:
    HAVE_NUMPY = False
    
try:
    import matplotlib.pyplot as plot
    HAVE_PYPLOT = True
except ImportError:
    HAVE_PYPLOT = False
    
class Heatmap(Module):
    cmd = 'heatmap'
    description = 'Creates a heatmap representation of a similarity matrix'
    
    def __init__(self):
        super(Heatmap, self).__init__()
        self.parser.add_argument('-s', '--ssdeep', type=str, help='Create a heatmap based on ssdeep')
        self.parser.add_argument('-c', '--chunks', type=str, help='Create a heatmap based on the hashed chunks of samples')
        self.parser.add_argument('-f', '--functions', type=str, help='Create a heatmap based on function name matches')
        self.parser.add_argument('-b', '--bodies', type=str, help='Create a heatmap based on user-defined function bodies')
        
    def usage(self):
            print('usage: heatmap [-h][-s <raw>][-s <decoded>][-c <raw>][-c <decoded>]\n[-f <raw>][-f <decoded>][-b <raw>][-b <decoded>]')
    
    def run(self):             
        super(Heatmap, self).run()
        if self.args is None:
            return
               
        # Check dependencies
        if not HAVE_NUMPY:
            print_error('Missing dependency, install numpy (`pip install numpy`)')
            return
            
        if not HAVE_PYPLOT:
            print_error('Missing dependency, install matplotlib (`pip install matplotlib`)')
            return            
                  
        # Get Viper's root path
        viper_path = get_viper_path(__project__.get_path())            
        
        # Get project name
        project = __project__.name    
        if project is None:
            project = ''
             
        if self.args.ssdeep == 'raw': 
            try:
                matrix = numpy.load(viper_path + '/data/matrix/ssdeep(raw)(' + project + ').npy')
                labels_path = viper_path + '/data/labels/ssdeep(raw)(' + project + ')'
                self.draw_heatmap(matrix, labels_path)
            except IOError:
                print_error('The required matrix has not been created. Run the matrix command and then try again')
            
        elif self.args.ssdeep == 'decoded':
            try:
                matrix = numpy.load(viper_path + '/data/matrix/ssdeep(decoded)(' + project + ').npy')
                labels_path = viper_path + '/data/labels/ssdeep(decoded)(' + project + ')'
                self.draw_heatmap(matrix, labels_path)
            except IOError:
                print_error('The required matrix has not been created. Run the matrix command and then try again')
            
        elif self.args.functions == 'raw':
            try:
                matrix = numpy.load(viper_path + '/data/matrix/funcs(raw)(' + project + ').npy')
                labels_path = viper_path + '/data/labels/funcs(raw)(' + project + ')'
                self.draw_heatmap(matrix, labels_path)
            except IOError:
                print_error('The required matrix has not been created. Run the matrix command and then try again')
            
        elif self.args.functions == 'decoded':
            try:
                matrix = numpy.load(viper_path + '/data/matrix/funcs(decoded)(' + project + ').npy')
                labels_path = viper_path + '/data/labels/funcs(decoded)(' + project + ')'
                self.draw_heatmap(matrix, labels_path)
            except IOError:
                print_error('The required matrix has not been created. Run the matrix command and then try again')
            
        elif self.args.chunks == 'raw':
            try:
                matrix = numpy.load(viper_path + '/data/matrix/chunks(raw)(' + project + ').npy')
                labels_path = viper_path + '/data/labels/chunks(raw)(' + project + ')'
                self.draw_heatmap(matrix, labels_path)
            except IOError:
                print_error('The required matrix has not been created. Run the matrix command and then try again')
            
        elif self.args.chunks == 'decoded':
            try:
                matrix = numpy.load(viper_path + '/data/matrix/chunks(decoded)(' + project + ').npy')
                labels_path = viper_path + '/data/labels/chunks(decoded)(' + project + ')'
                self.draw_heatmap(matrix, labels_path)
            except IOError:
                print_error('The required matrix has not been created. Run the matrix command and then try again')
            
        elif self.args.bodies == 'raw':
            try:
                matrix = numpy.load(viper_path + '/data/matrix/bodies(raw)(' + project + ').npy')
                labels_path = viper_path + '/data/labels/bodies(raw)(' + project + ')'
                self.draw_heatmap(matrix, labels_path)
            except IOError:
                print_error('The required matrix has not been created. Run the matrix command and then try again')
            
        elif self.args.bodies == 'decoded':
            try:
                matrix = numpy.load(viper_path + '/data/matrix/bodies(decoded)(' + project + ').npy')
                labels_path = viper_path +  '/data/labels/bodies(decoded)(' + project + ')'
                self.draw_heatmap(matrix, labels_path)    
            except IOError:
                print_error('The required matrix has not been created. Run the matrix command and then try again')                  
                       
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()

    def draw_heatmap(self, matrix, labels_path):     
        
        # Get labels
        with open(labels_path, 'r') as infile:
            sample_names = json.load(infile)
            
        lsize = 100/len(sample_names)
        
        # Print the matrix
        print(numpy.flipud(matrix))
        
        # Set up the heatmap
        fig, ax = plot.subplots()            
        heatmap = ax.pcolor(matrix, cmap=plot.cm.Blues)
        
        # Place the ticks in the middle of each cell
        ax.set_xticks(numpy.arange(matrix.shape[0])+0.5, minor=False)
        ax.set_yticks(numpy.arange(matrix.shape[1])+0.5, minor=False)
        
        # Set the labels
        ax.set_xticklabels(sample_names, minor=False)
        ax.set_yticklabels(sample_names, minor=False)
        
        # Rotate the x-axis labels
        plot.xticks(rotation=90)
        
        # Set the label size
        ax.tick_params(axis='x', labelsize=lsize)
        ax.tick_params(axis='y', labelsize=lsize)
        
        # Turn off all the ticks
        ax = plot.gca()
        
        for t in ax.xaxis.get_major_ticks():
            t.tick1On = False
            t.tick2On = False
        for t in ax.yaxis.get_major_ticks():
            t.tick1On = False
            t.tick2On = False
            
        plot.tight_layout()
        
        plot.show()
