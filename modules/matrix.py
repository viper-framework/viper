import json
import sys

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.project import __project__
from viper.core.storage import get_sample_path
from viper.common.utils import get_viper_path

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False
    
try:
    import numpy
    HAVE_NUMPY = True
except ImportError:
    HAVE_NUMPY = False

class Matrix(Module):
    cmd = 'matrix'
    description = 'Creates similarity matrices based on a given measure of similarity'
    
    def __init__(self):
        super(Matrix, self).__init__()
        self.parser.add_argument('-s', '--ssdeep', type=str, help='Create a heatmap based on ssdeep')
        self.parser.add_argument('-c', '--chunks', type=str, help='Create a heatmap based on the hashed chunks of samples')
        self.parser.add_argument('-f', '--functions', type=str, help='Create a heatmap based on function name matches')
        self.parser.add_argument('-b', '--bodies', type=str, help='Create a heatmap based on user-defined function bodies')
        self.parser.add_argument('-d', '--difference', type=str, help='Create a difference matrix')
        
    def usage(self):
            print('usage: matrix [-h][-s <raw>][-s <decoded>][-c <raw>][-c <decoded>]\n[-f <raw>][-f <decoded>][-b <raw>][-b <decoded>]\n[-d <ssdeep>][-d <chunks>][-d <functions>][-d <bodies>]')

    def run(self):
        super(Matrix, self).run()
        if self.args is None:
            return
        
        # Dependency checks        
        if not HAVE_PYDEEP:
           print_error('Missing dependency, install pydeep (`pip install pydeep`)')
           return           
        if not HAVE_NUMPY:
            print_error('Missing dependency, install numpy (`pip install numpy`)')
            return    

#---------------------------------Preliminary----------------------------------
       
        print('Creating matrix...')           
        
        # Get Viper's root path
        viper_path = get_viper_path(__project__.get_path()) 
        
        # Check that the labels and matrix folders exist
        directory = viper_path + '/data/labels'
        if not os.path.exists(directory):
            os.makedirs(directory)
            
        directory = viper_path + '/data/matrix'
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        # Get the project name
        project = __project__.name
        if project is None:
            project = ''
        
        # Retrieve all the samples from the database
        db = Database()
        samples = db.find(key='all')
        
        # Count the number of samples
        total = len(samples)      
        print('Total samples: ' + str(total))
        
        # Create a list of samples
        sample_names = []
        for sample in samples:
            sample_names.append(str(sample.sha256))
            
        # Create an appropriately-sized matrix
        matrix = [[0 for x in xrange(total)] for x in xrange(total)]
                      
#-----------------------------------Ssdeep-------------------------------------        
        
        if self.args.ssdeep == 'raw':   
               
            # Create and save a list of sample labels
            sample_labels = []
            for sample in samples:
                sample_labels.append(str(sample.name))            
            with open(viper_path + '/data/labels/ssdeep(raw)(' + project + ')', 'w') as outfile:
                json.dump(sample_labels, outfile)              
                        
            # Populate the similarity matrix
            count = 0
            total2 = 0
            mini = matrix[0][0]
            maxi = matrix[0][0]
            for x in range(0, total):
                path1 = get_sample_path(sample_names[x])         
                
                for y in range(0, total):                     
                    path2 = get_sample_path(sample_names[y])                
                    matrix[x][y] = self.compare_ssdeep(path1, path2)
                    
                    if(matrix[x][y] > 0):  
                        total2 += matrix[x][y]
                        if(matrix[x][y] < mini):
                            mini = matrix[x][y]
                        if(matrix[x][y] > maxi):
                            maxi = matrix[x][y]
                        count += 1   
                        
            # Display the matrix
            arr = numpy.array(matrix)
            print(numpy.flipud(arr))
                            
            # Save the matrix for later use                  
            numpy.save(viper_path + '/data/matrix/ssdeep(raw)(' + project + ')', matrix)
                                      
            # Print a summary
            self.print_summary(count, mini, maxi, total2)
            
        elif self.args.ssdeep == 'decoded':           
                
            # Check if all samples have been decoded
            if self.all_decoded(sample_names):  
                
                # Create and save a list of sample labels
                sample_labels = []
                for sample in samples:
                    sample_labels.append(str(sample.name.split('.', 1)[0]))          
                with open(viper_path + '/data/labels/ssdeep(decoded)(' + project + ')', 'w') as outfile:
                    json.dump(sample_labels, outfile)        
                  
                # Create an appropriately-sized matrix
                matrix = [[0 for x in xrange(total)] for x in xrange(total)]
                
                # Populate the similarity matrix
                count = 0
                total2 = 0
                mini = matrix[0][0]
                maxi = matrix[0][0]
                for x in range(0, total):
                    path1 = get_sample_path(sample_names[x]) + '(decoded)'         
                    
                    for y in range(0, total):                        
                        path2 = get_sample_path(sample_names[y]) + '(decoded)'               
                        matrix[x][y] = self.compare_ssdeep(path1, path2)
                        
                        if(matrix[x][y] > 0):
                            total2 += matrix[x][y]
                            if(matrix[x][y] < mini):
                                mini = matrix[x][y]
                            if(matrix[x][y] > maxi):
                                maxi = matrix[x][y]
                            count += 1   
                
                # Save the matrix for later use                             
                numpy.save(viper_path + '/data/matrix/ssdeep(decoded)(' + project + ')', matrix)
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))
                
                # Print a summary
                self.print_summary(count, mini, maxi, total2)
                
#-------------------------------Hashed Chunks----------------------------------
        
        elif self.args.chunks == 'raw':           
            
            # Check if all samples have been hashed
            if(self.all_chunked_raw(sample_names)):
                
                # Create and save a list of sample labels
                sample_labels = []
                for sample in samples:
                    sample_labels.append(str(sample.name))            
                with open(viper_path + '/data/labels/chunks(raw)(' + project + ')', 'w') as outfile:
                    json.dump(sample_labels, outfile)                             
                
                # Populate the similarity matrix
                count = 0
                total2 = 0
                mini = matrix[0][0]
                maxi = matrix[0][0]
                for x in range(0, total):
                    path1 = get_sample_path(sample_names[x]) + '(raw)'
                    
                    for y in range(0, total):                                       
                        path2 = get_sample_path(sample_names[y]) + '(raw)'                
                        matrix[x][y] = self.compare_chunks(path1, path2)
                        
                        if(matrix[x][y] > 0):
                                total2 += matrix[x][y]
                                if(matrix[x][y] < mini):
                                    mini = matrix[x][y]
                                if(matrix[x][y] > maxi):
                                    maxi = matrix[x][y]
                                count += 1
                                
                # Save the matrix for later use               
                numpy.save(viper_path + '/data/matrix/chunks(raw)(' + project + ')', matrix)
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))
                
                # Print a summary
                self.print_summary(count, mini, maxi, total2)    
             
        elif self.args.chunks == 'decoded':          
                
            # Check if all samples have been hashed
            if self.all_chunked_decoded(sample_names): 
                
                # Create and save a list of sample labels
                sample_labels = []
                for sample in samples:
                    sample_labels.append(str(sample.name))            
                with open(viper_path + '/data/labels/chunks(decoded)(' + project + ')', 'w') as outfile:
                    json.dump(sample_labels, outfile)  
                
                # Populate the similarity matrix
                count = 0
                total2 = 0
                mini = matrix[0][0]
                maxi = matrix[0][0]
                for x in range(0, total):
                    path1 = get_sample_path(sample_names[x]) + '(decoded)'
                    
                    for y in range(0, total):                                       
                        path2 = get_sample_path(sample_names[y]) + '(decoded)'                
                        matrix[x][y] = self.compare_chunks(path1, path2)
                        
                        if(matrix[x][y] > 0):
                                total2 += matrix[x][y]
                                if(matrix[x][y] < mini):
                                    mini = matrix[x][y]
                                if(matrix[x][y] > maxi):
                                    maxi = matrix[x][y]
                                count += 1
                                
                # Save the matrix for later use                 
                numpy.save(viper_path + '/data/matrix/chunks(decoded)(' + project + ')', matrix)    
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))
                
                # Print a summary
                self.print_summary(count, mini, maxi, total2)
                    
#----------------------------------Functions-----------------------------------
        
        elif self.args.functions == 'raw': 
            
            # Check if all samples have had their functions extracted
            if self.all_functions_raw(sample_names):
                          
                # Create and save a list of sample labels
                sample_labels = []
                for sample in samples:
                    sample_labels.append(str(sample.name))            
                with open(viper_path + '/data/labels/funcs(raw)(' + project + ')', 'w') as outfile:
                    json.dump(sample_labels, outfile)       
                
                # Populate the similarity matrix
                count = 0
                total2 = 0
                mini = matrix[0][0]
                maxi = matrix[0][0]
                for x in range(0, total):
                    path1 = get_sample_path(sample_names[x]) + '(raw)'
                    
                    for y in range(0, total):                                       
                        path2 = get_sample_path(sample_names[y]) + '(raw)'
                    
                        matrix[x][y] = self.compare_funcs(path1, path2)
                        
                        if(matrix[x][y] > 0):
                                total2 += matrix[x][y]
                                if(matrix[x][y] < mini):
                                    mini = matrix[x][y]
                                if(matrix[x][y] > maxi):
                                    maxi = matrix[x][y]
                                count += 1
                                
                # Save the matrix for later use                 
                numpy.save(viper_path + '/data/matrix/funcs(raw)(' + project + ')', matrix)
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))  
                
                # Print a summary
                self.print_summary(count, mini, maxi, total2)            
            
        elif self.args.functions == 'decoded':                              
                    
            # Check if all samples have had their functions extracted
            if self.all_functions_decoded(sample_names):   
                
                # Create and save a list of sample labels
                sample_labels = []
                for sample in samples:
                    sample_labels.append(str(sample.name))            
                with open(viper_path + '/data/labels/funcs(decoded)(' + project + ')', 'w') as outfile:
                    json.dump(sample_labels, outfile)
                
                # Populate the similarity matrix
                count = 0
                total2 = 0
                mini = matrix[0][0]
                maxi = matrix[0][0]
                for x in range(0, total):
                    path1 = get_sample_path(sample_names[x]) + '(decoded)'
                    
                    for y in range(0, total):                                       
                        path2 = get_sample_path(sample_names[y]) + '(decoded)'
                    
                        matrix[x][y] = self.compare_funcs(path1, path2)
                        
                        if(x == y and matrix[x][y] == 0):   
                            matrix[x][y] = 1                        
                        
                        if(matrix[x][y] > 0):
                                total2 += matrix[x][y]
                                if(matrix[x][y] < mini):
                                    mini = matrix[x][y]
                                if(matrix[x][y] > maxi):
                                    maxi = matrix[x][y]
                                count += 1
                                
                # Save the matrix for later use                
                numpy.save(viper_path + '/data/matrix/funcs(decoded)(' + project + ')', matrix)
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))     
                
                # Print a summary
                self.print_summary(count, mini, maxi, total2)        
                
#-----------------------------------Bodies-------------------------------------                

        elif self.args.bodies == 'raw':    
            
            # Check if all samples have had their function bodies extracted
            if self.all_bodies_raw(sample_names):
                             
                # Create and save a list of sample labels
                sample_labels = []
                for sample in samples:
                    if(str(sample.name) != 'ud.txt' and str(sample.name) != 'mad1.txt'):
                        sample_labels.append(str(sample.name))
                with open(viper_path + '/data/labels/bodies(raw)(' + project + ')', 'w') as outfile:
                    json.dump(sample_labels, outfile)     
                
                # Populate the similarity matrix
                count = 0
                total2 = 0
                mini = matrix[0][0]
                maxi = matrix[0][0]
                for x in range(0, total):
                    path1 = get_sample_path(sample_names[x]) + '(raw)'
                    
                    for y in range(0, total):                                       
                        path2 = get_sample_path(sample_names[y]) + '(raw)' 
                        
                        matrix[x][y] = self.compare_bodies(path1, path2)
                        
                        if(x == y and matrix[x][y] == 0):   
                            matrix[x][y] = 1
                        
                        if(matrix[x][y] > 0):
                            total2 += matrix[x][y]
                            if(matrix[x][y] < mini):
                                mini = matrix[x][y]
                            if(matrix[x][y] > maxi):
                                maxi = matrix[x][y]
                            count += 1
                                    
                # Save the matrix for later use               
                numpy.save(viper_path + '/data/matrix/bodies(raw)(' + project + ')', matrix)
    
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))
                
                # Print a summary
                self.print_summary(count, mini, maxi, total2)    
             
        elif self.args.bodies == 'decoded':              
                
            # Check if all samples have had their function bodies extracted
            if self.all_bodies_decoded(sample_names): 
                
                # Create and save a list of sample labels
                sample_labels = []
                for sample in samples:
                    sample_labels.append(str(sample.name))            
                with open(viper_path + '/data/labels/bodies(decoded)(' + project + ')', 'w') as outfile:
                    json.dump(sample_labels, outfile)
                
                # Populate the similarity matrix
                count = 0
                total2 = 0
                mini = matrix[0][0]
                maxi = matrix[0][0]
                for x in range(0, total):
                    path1 = get_sample_path(sample_names[x]) + '(decoded)'
                    
                    for y in range(0, total):                                                              
                        path2 = get_sample_path(sample_names[y]) + '(decoded)'   
                        
                        matrix[x][y] = self.compare_bodies(path1, path2)
                        
                        if(x == y and matrix[x][y] == 0):   
                            matrix[x][y] = 1
                        
                        if(matrix[x][y] > 0):
                                total2 += matrix[x][y]
                                if(matrix[x][y] < mini):
                                    mini = matrix[x][y]
                                if(matrix[x][y] > maxi):
                                    maxi = matrix[x][y]
                                count += 1
                                
                # Save the matrix for later use                
                numpy.save(viper_path + '/data/matrix/bodies(decoded)(' + project + ')', matrix)    
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr)) 
                
                # Print a summary
                self.print_summary(count, mini, maxi, total2)    
            
#---------------------------------Difference-----------------------------------       
        
        elif self.args.difference == 'ssdeep':
            
            # Create and save a list of sample labels
            sample_labels = []
            for sample in samples:
                sample_labels.append(str(sample.name))            
            with open(viper_path + '/data/labels/diff(ssdeep)(' + project + ')', 'w') as outfile:
                json.dump(sample_labels, outfile) 
            
            have_matrices = True
            
            try:
                raw = numpy.load(viper_path + '/data/matrix/ssdeep(raw)(' + project + ').npy')                
            except IOError:
                have_matrices = False
                print_error('A raw matrix has not yet been created. Use the matrix command to create it')
             
            try:
                decoded = numpy.load(viper_path + '/data/matrix/ssdeep(decoded)(' + project + ').npy')               
            except IOError:
                have_matrices = False
                print_error('A decoded matrix has not yet been created. Use the matrix command to create it')
            
            if have_matrices:
                count = 0
                total = 0
                num_pos = 0
                num_neg = 0
                matrix = numpy.subtract(decoded, raw)
                for x in matrix:
                    for y in x:
                        if(y != 0):
                            count += 1
                            total += y
                            if(y < 0):
                                num_neg += 1
                            else:
                                num_pos += 1
                                
                # Save the matrix for later use                              
                numpy.save(viper_path + '/data/matrix/diff(ssdeep)(' + project + ')', matrix)
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))
                
                # Print a summary
                print_info('Summary')
                print('Number of differences: ' + str(count))
                print('Number of positive distances: ' + str(num_pos))
                print('Number of negative distances: ' + str(num_neg))
                print('Sum of all differences: ' + str(total))
                
        elif self.args.difference == 'chunks':
            
            # Create and save a list of sample labels
            sample_labels = []
            for sample in samples:
                sample_labels.append(str(sample.name))            
            with open(viper_path + '/data/labels/diff(chunks)(' + project + ')', 'w') as outfile:
                json.dump(sample_labels, outfile) 
            
            have_matrices = True
            
            try:
                raw = numpy.load(viper_path + '/data/matrix/chunks(raw)(' + project + ').npy')                
            except IOError:
                have_matrices = False
                print_error('A raw matrix has not yet been created. Use the matrix command to create it')
             
            try:
                decoded = numpy.load(viper_path + '/data/matrix/chunks(decoded)(' + project + ').npy')               
            except IOError:
                have_matrices = False
                print_error('A decoded matrix has not yet been created. Use the matrix command to create it')
            
            if have_matrices:
                count = 0
                total = 0
                num_pos = 0
                num_neg = 0
                matrix = numpy.subtract(decoded, raw)
                for x in matrix:
                    for y in x:
                        if(y != 0):
                            count += 1
                            total += y
                            if(y < 0):
                                num_neg += 1
                            else:
                                num_pos += 1
                                
                # Save the matrix for later use                              
                numpy.save(viper_path + '/data/matrix/diff(chunks)(' + project + ')', matrix)
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))
                
                # Print a summary
                print_info('Summary')
                print('Number of differences: ' + str(count))
                print('Number of positive distances: ' + str(num_pos))
                print('Number of negative distances: ' + str(num_neg))
                print('Sum of all differences: ' + str(total))
                
        elif self.args.difference == 'funcs':
            
            # Create and save a list of sample labels
            sample_labels = []
            for sample in samples:
                sample_labels.append(str(sample.name))            
            with open(viper_path + '/data/labels/diff(funcs)(' + project + ')', 'w') as outfile:
                json.dump(sample_labels, outfile) 
            
            have_matrices = True
            
            try:
                raw = numpy.load(viper_path + '/data/matrix/funcs(raw)(' + project + ').npy')                
            except IOError:
                have_matrices = False
                print_error('A raw matrix has not yet been created. Use the matrix command to create it')
             
            try:
                decoded = numpy.load(viper_path + '/data/matrix/funcs(decoded)(' + project + ').npy')               
            except IOError:
                have_matrices = False
                print_error('A decoded matrix has not yet been created. Use the matrix command to create it')
            
            if have_matrices:
                count = 0
                total = 0
                num_pos = 0
                num_neg = 0
                matrix = numpy.subtract(decoded, raw)
                for x in matrix:
                    for y in x:
                        if(y != 0):
                            count += 1
                            total += y
                            if(y < 0):
                                num_neg += 1
                            else:
                                num_pos += 1
                                
                # Save the matrix for later use                              
                numpy.save(viper_path + '/data/matrix/diff(functions)(' + project + ')', matrix)
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))
                
                # Print a summary
                print_info('Summary')
                print('Number of differences: ' + str(count))
                print('Number of positive distances: ' + str(num_pos))
                print('Number of negative distances: ' + str(num_neg))
                print('Sum of all differences: ' + str(total))
                
        elif self.args.difference == 'bodies':
            
            # Create and save a list of sample labels
            sample_labels = []
            for sample in samples:
                sample_labels.append(str(sample.name))            
            with open(viper_path + '/data/labels/diff(bodies)(' + project + ')', 'w') as outfile:
                json.dump(sample_labels, outfile) 
            
            have_matrices = True
            
            try:
                raw = numpy.load(viper_path + '/data/matrix/bodies(raw)(' + project + ').npy')                
            except IOError:
                have_matrices = False
                print_error('A raw matrix has not yet been created. Use the matrix command to create it')
             
            try:
                decoded = numpy.load(viper_path + '/data/matrix/bodies(decoded)(' + project + ').npy')               
            except IOError:
                have_matrices = False
                print_error('A decoded matrix has not yet been created. Use the matrix command to create it')
            
            if have_matrices:
                count = 0
                total = 0
                num_pos = 0
                num_neg = 0
                matrix = numpy.subtract(decoded, raw)
                for x in matrix:
                    for y in x:
                        if(y != 0):
                            count += 1
                            total += y
                            if(y < 0):
                                num_neg += 1
                            else:
                                num_pos += 1
                                
                # Save the matrix for later use                              
                numpy.save(viper_path + '/data/matrix/diff(bodies)(' + project + ')', matrix)
                
                # Display the matrix
                arr = numpy.array(matrix)
                print(numpy.flipud(arr))
                
                # Print a summary
                print_info('Summary')
                print('Number of differences: ' + str(count))
                print('Number of positive distances: ' + str(num_pos))
                print('Number of negative distances: ' + str(num_neg))
                print('Sum of all differences: ' + str(total))
                
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()                                 
    
#----------------------------------Helpers-------------------------------------

#----------------------------Comparison Functions------------------------------

    def compare_ssdeep(self, file1, file2):
        return pydeep.compare(pydeep.hash_file(file1), pydeep.hash_file(file2))
        
    def compare_chunks(self, file1, file2):
        
        # Open the hashed chunk lists for each file
        with open(file1 + '(chunks)') as f1:
            contents1 = f1.readlines();
        with open(file2 + '(chunks)') as f2:
            contents2 = f2.readlines();
            
        # Remove duplicates
        contents1 = list(set(contents1))
        contents2 = list(set(contents2))
        
        # Select the longest list as the total      
        count = max(len(contents1), len(contents2))
        if(count == 0):
            return 0
        
        # Count the hashed chunk matches
        matches = 0.0
        for linehash1 in contents1:
            for linehash2 in contents2:
                if(pydeep.compare(linehash1, linehash2) > 40):
                    matches += 1
                    break
                
        return int(round((matches/count) * 100))
        
    def compare_funcs(self, file1, file2):
        
        # Open the function name lists for each file
        with open(file1 + '(functions)') as f1:
            contents1 = f1.readlines();
        with open(file2 + '(functions)') as f2:
            contents2 = f2.readlines();
        
        # Remove duplicates
        contents1 = list(set(contents1))
        contents2 = list(set(contents2))
        
        # Select the longest list as the total      
        count = max(len(contents1), len(contents2))
        if(count == 0):
            return 0
        
        # Count the function name matches
        matches = 0.0
        for func_name in contents1:
            if func_name in contents2:
                matches += 1       
                
        return int(round((matches/count) * 100))
        
    def compare_bodies(self, file1, file2):
        
        # Open the function body lists for each file
        with open(file1 + '(bodies)') as f1:
            contents1 = f1.readlines();
        with open(file2 + '(bodies)') as f2:
            contents2 = f2.readlines();
            
        # Remove duplicates
        contents1 = list(set(contents1))
        contents2 = list(set(contents2))
        
        # Select the longest list as the total      
        count = max(len(contents1), len(contents2))
        if(count == 0):
            return 0
        
        # Count the function name matches
        matches = 0.0
        for body in contents1:
            if body in contents2:
                matches += 1
            
        return int(round((matches/count) * 100))
        
    def compare_html(self, file1, file2):
        
        # Open the HTML dumps for each file
        with open(file1 + '(html)') as f1:
            contents1 = f1.read();
        with open(file2 + '(html)') as f2:
            contents2 = f2.read();    
            
        if(contents1 == 'failed' or contents2 == 'failed'):
            return 0
            
        return pydeep.compare(pydeep.hash_file(file1 + '(html)'), pydeep.hash_file(file2 + '(html)'))
 
#---------------------------Validation Functions-------------------------------
       
    def all_decoded(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(decoded)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all samples have been decoded. Run the decode_all command and then try again')
                 return False
        return True
        
    def all_chunked_raw(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(raw)(chunks)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all raw samples have been hashed. Run the chunks_all command and then try again')
                 return False
        return True
        
    def all_chunked_decoded(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(decoded)(chunks)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all decoded samples have been hashed. Run the chunks_all command and then try again')
                 return False
        return True
        
    def all_functions_raw(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(raw)(functions)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all raw samples have had their function names extracted. Run the functions_all command and then try again')
                 return False
        return True
        
    def all_functions_decoded(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(decoded)(functions)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all decoded samples have had their function names extracted. Run the functions_all command and then try again')
                 return False
        return True
    
    def all_bodies_raw(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(raw)(bodies)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all raw samples have had their function bodies extracted. Run the bodies_all command and then try again')
                 return False
        return True
        
    def all_bodies_decoded(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(decoded)(bodies)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all decoded samples have had their function bodies extracted. Run the bodies_all command and then try again')
                 return False
        return True
        
    def all_html_raw(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(raw)(html)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all raw samples have had their html extracted. Run the html_dump_all command and then try again')
                 return False
        return True
        
    def all_html_decoded(self, sample_names):
        for sample in sample_names:
            path = get_sample_path(sample) + '(decoded)(html)'
            try:
                f = open(path)
                f.close()
            except IOError:
                 print_error('Not all decoded samples have had their html extracted. Run the html_dump_all command and then try again')
                 return False
        return True

#----------------------------Printing Functions--------------------------------
       
    def print_summary(self, count, mini, maxi, total):
        print_info('Summary')
        print('Number of matches: ' + str(count))
        print('Lowest match: ' + str(mini))
        print('Highest match: ' + str(maxi))
        print('Sum of all matches: ' + str(total))
