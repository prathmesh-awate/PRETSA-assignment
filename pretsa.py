from anytree import AnyNode, PreOrderIter # anynode- represent node in a tree, preorderiter: iterate over tree in pre order
from levenshtein import levenshtein #edit distance between two strings
import sys #command line system arguments
from scipy.stats import wasserstein_distance #compare 2 probability distribution
from scipy.stats import normaltest # is sample coming from a normal distribution?
import pandas as pd # data manipulation tables
import numpy as np # arrays and matrices
import time #time related functions 
from numpy.random import laplace
from authorization import authorization

import getpass
import hashlib
import os
import random 
import string

PASSWORD_FILE = "password_hash.txt"  

class Pretsa:
    #initialise the class by processing the event log into a tree structure
    #where each node corresponds to an activity 
    #track cases and sequences of activities
    def __init__(self,eventLog, epsilon='', user_role=''):
        self.auth = authorization(user_role)
        self.password_hash = None 
        self._load_or_set_password()
        root = AnyNode(id='Root', name="Root", cases=set(), sequence="", annotation=dict(),sequences=set())
        current = root
        currentCase = ""
        caseToSequenceDict = dict()
        sequence = None
        self.__caseIDColName = "Case ID"
        self.__activityColName = "Activity"
        self.__annotationColName = "Duration"
        self.__constantEventNr = "Event_Nr"
        self.__annotationDataOverAll = dict()
        self.__normaltest_alpha = 0.05
        self.__normaltest_result_storage = dict()
        self.__normalTCloseness = True
        for index, row in eventLog.iterrows():
            activity = row[self.__activityColName]
            annotation = row[self.__annotationColName]
            if row[self.__caseIDColName] != currentCase:
                current = root
                if not sequence is None:
                    caseToSequenceDict[currentCase] = sequence
                    current.sequences.add(sequence)
                currentCase = row[self.__caseIDColName]
                current.cases.add(currentCase)
                sequence = ""
            childAlreadyExists = False
            sequence = sequence + "@" + activity
            for child in current.children:
                if child.name == activity:
                    childAlreadyExists = True
                    current = child
            if not childAlreadyExists:
                node = AnyNode(id=index, name=activity, parent=current, cases=set(), sequence=sequence, annotations=dict())
                current = node
            current.cases.add(currentCase)
            current.annotations[currentCase] = annotation
            self.__addAnnotation(annotation, activity)
        #Handle last case
        caseToSequenceDict[currentCase] = sequence
        root.sequences.add(sequence)
        self._tree = root
        self._caseToSequenceDict = caseToSequenceDict
        self.__numberOfTracesOriginal = len(self._tree.cases)
        self._sequentialPrunning = True
        self.__setMaxDifferences()
        self.__haveAllValuesInActivitityDistributionTheSameValue = dict()
        self._distanceMatrix = self.__generateDistanceMatrixSequences(self._getAllPotentialSequencesTree(self._tree))
        self.epsilon = float(epsilon)
    
    def _generate_salt(self):
        #generate a random salt string
        salt_length = 16  
        salt = ''.join(random.choices(string.ascii_letters + string.digits, k=salt_length))
        return salt

    def _hashPassword(self, password, salt=None): 
        if not salt:
            salt = self._generate_salt()  # generate a new salt if not provided
        salted_password = password + salt  # combine password and salt
        return hashlib.sha256(salted_password.encode()).hexdigest(), salt
    
    def _load_or_set_password(self):
        #Load the stored password hash or prompt the user to set one if missing.
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "r") as f:
                stored_hash, stored_salt = f.read().strip().split(':')
                if stored_hash:  # Ensure the file isn't empty
                    self.password_hash = stored_hash
                    self.password_salt = stored_salt  # Store the salt for later comparison
                    return

        # if the file is missing or empty, ask for a new password
        self._set_password()
    def _set_password(self):
        """Prompts the user to set a secure password and stores its hash."""
        password = getpass.getpass("Set your password: ")
        self.password_hash, self.password_salt = self._hashPassword(password)

       # Save the hashed password and salt to the file (separated by a colon)
        with open(PASSWORD_FILE, "w") as f:
            f.write(f"{self.password_hash}:{self.password_salt}")
        print("Password set successfully!")

    def _ask_for_password(self):
        """Asks for the password before executing sensitive operations."""
        attempts = 3
        while attempts > 0:
            user_input = getpass.getpass("Enter password: ")
            hashed_input, _ = self._hashPassword(user_input, self.password_salt)
            if hashed_input == self.password_hash:
                return True
            else:
                print(f"Incorrect password. {attempts-1} attempts remaining.")
                attempts -= 1
        print("Access denied.")
        return False

    def __generateLaplaceNoise(self, sensitivity):
        scale = self.epsilon/ sensitivity
        return laplace(loc=0, scale=scale)
    #adds annotations to a dictionary for each activity which will be used for t-closeness checks
    def __addAnnotation(self, annotation, activity):
        dataForActivity = self.__annotationDataOverAll.get(activity, None)
        if dataForActivity is None:
            self.__annotationDataOverAll[activity] = []
            dataForActivity = self.__annotationDataOverAll[activity]
        dataForActivity.append(annotation)
    #compute maximum difference between in annotations in each activity 
    def __setMaxDifferences(self):
        self.annotationMaxDifferences = dict()
        for key in self.__annotationDataOverAll.keys():
            maxVal = max(self.__annotationDataOverAll[key])
            minVal = min(self.__annotationDataOverAll[key])
            self.annotationMaxDifferences[key] = abs(maxVal - minVal)

    #check if a node violates t closeness by comparing the distribution of annotations with the overall distribution of the activity
    def _violatesTCloseness(self, activity, annotations, t, cases):
        distributionActivity = self.__annotationDataOverAll[activity]
        maxDifference = self.annotationMaxDifferences[activity]
        #Consider only data from cases still in node
        distributionEquivalenceClass = []
        casesInClass = cases.intersection(set(annotations.keys()))
        for caseInClass in casesInClass:
            distributionEquivalenceClass.append(annotations[caseInClass])
        if len(distributionEquivalenceClass) == 0: #No original annotation is left in the node
            return False
        if maxDifference == 0.0: #All annotations have the same value(most likely= 0.0)
            return
        if self.__normalTCloseness == True:
            return ((wasserstein_distance(distributionActivity,distributionEquivalenceClass)/maxDifference) >= t)
        else:
            return self._violatesStochasticTCloseness(distributionActivity,distributionEquivalenceClass,t,activity)

    #prunes tree or removes traces that k-anonymity or t-closeness
    def _treePrunning(self, k,t):
        cutOutTraces = set()
        for node in PreOrderIter(self._tree):
            if node != self._tree:
                node.cases = node.cases.difference(cutOutTraces)
                if len(node.cases) < k or self._violatesTCloseness(node.name, node.annotations, t, node.cases):
                    cutOutTraces = cutOutTraces.union(node.cases)
                    self._cutCasesOutOfTreeStartingFromNode(node,cutOutTraces)
                    if self._sequentialPrunning:
                        return cutOutTraces
        return cutOutTraces

    #This method removes specific traces (cases) from the tree starting from a given node.
    def _cutCasesOutOfTreeStartingFromNode(self,node,cutOutTraces,tree=None):
        if tree == None:
            tree = self._tree
        current = node
        try:
            tree.sequences.remove(node.sequence)
        except KeyError:
            pass
        while current != tree:
            current.cases = current.cases.difference(cutOutTraces)
            if len(current.cases) == 0:
                node = current
                current = current.parent
                node.parent = None
            else:
                current = current.parent

    #This method retrieves all potential sequences from the tree.
    def _getAllPotentialSequencesTree(self, tree):
        return tree.sequences

    #This method adds a trace (case) to the tree according to a sequence.
    def _addCaseToTree(self, trace, sequence,tree=None):
        if tree == None:
            tree = self._tree
        if trace != "":
            activities = sequence.split("@")
            currentNode = tree
            tree.cases.add(trace)
            for activity in activities:
                for child in currentNode.children:
                    if child.name == activity:
                        child.cases.add(trace)
                        currentNode = child
                        break

    #This method combines a set of traces with the existing tree based on their sequence similarity.
    def __combineTracesAndTree(self, traces):
        #We transform the set of sequences into a list and sort it, to discretize the behaviour of the algorithm
        sequencesTree = list(self._getAllPotentialSequencesTree(self._tree))
        sequencesTree.sort()
        for trace in traces:
            bestSequence = ""
            #initial value as high as possible
            lowestDistance = sys.maxsize
            traceSequence = self._caseToSequenceDict[trace]
            for treeSequence in sequencesTree:
                currentDistance = self._getDistanceSequences(traceSequence, treeSequence)
                if currentDistance < lowestDistance:
                    bestSequence = treeSequence
                    lowestDistance = currentDistance
            self._overallLogDistance += lowestDistance
            self._addCaseToTree(trace, bestSequence)
    
    #Runs the privacy-preserving algorithm, combining pruning and sequence matching to anonymize the event log while maintaining privacy.
    def runPretsa(self,k,t,normalTCloseness=True):
        if not self._ask_for_password():
            return "Operation canceled due to incorrect password."
    
        self.auth.check_access('modify_all') 
        self.__normalTCloseness = normalTCloseness
        # privacy_score = self.compute_privacy_score(k, t)
        # print("Privacy Score: ",privacy_score)
        if not self.__normalTCloseness:
            self.__haveAllValuesInActivitityDistributionTheSameValue = dict()
        self._overallLogDistance = 0.0
        if self._sequentialPrunning:
            cutOutCases = set()
            cutOutCase = self._treePrunning(k,t)
            while len(cutOutCase) > 0:
                self.__combineTracesAndTree(cutOutCase)
                cutOutCases = cutOutCases.union(cutOutCase)
                cutOutCase = self._treePrunning(k,t)
        else:
            cutOutCases = self._treePrunning(k,t)
            self.__combineTracesAndTree(cutOutCases)
        return cutOutCases, self._overallLogDistance

    #This method generates a new annotation for a given activity, typically used for adding new data points or modifying existing ones based on statistical tests.
    def __generateNewAnnotation(self, activity):
        #normaltest works only with more than 8 samples
        if(len(self.__annotationDataOverAll[activity])) >=8 and activity not in self.__normaltest_result_storage.keys():
            stat, p = normaltest(self.__annotationDataOverAll[activity])
        else:
            p = 1.0
        self.__normaltest_result_storage[activity] = p
        if self.__normaltest_result_storage[activity] <= self.__normaltest_alpha:
            mean = np.mean(self.__annotationDataOverAll[activity])
            std = np.std(self.__annotationDataOverAll[activity])
            randomValue = np.random.normal(mean, std)
        else:
            randomValue = np.random.choice(self.__annotationDataOverAll[activity])
        if randomValue < 0:
            randomValue = 0

        # Adding Laplace noise to the generated annotation
        sensitivity = self.annotationMaxDifferences.get(activity, 1.0)
        laplace_noise = self.__generateLaplaceNoise(sensitivity)
        return max(0, laplace_noise + randomValue)

    #This method creates and returns a dictionary representing an event, which includes details about a given case and node.
    def getEvent(self,case,node):
        event = {
            self.__activityColName: node.name,
            self.__caseIDColName: case,
            self.__annotationColName: node.annotations.get(case, self.__generateNewAnnotation(node.name)),
            self.__constantEventNr: node.depth
        }
        return event

    #retrieves all events associated with a given node in the tree structure and returns them as a list.
    def getEventsOfNode(self, node):
        events = []
        if node != self._tree:
            events = events + [self.getEvent(case, node) for case in node.cases]
        return events

    #Returns the privatised event log after anonymization, sorted by case ID and event number.
    def getPrivatisedEventLog(self):
        self.auth.check_access('view_all')
        events = []
        self.__normaltest_result_storage = dict()
        nodeEvents = [self.getEventsOfNode(node) for node in PreOrderIter(self._tree)]
        for node in nodeEvents:
            events.extend(node)
        
        # Applying differential privacy on event annotations
        for event in events:
            event[self.__annotationColName] = self.__generateNewAnnotation(event[self.__activityColName])
        eventLog = pd.DataFrame(events)
        if not eventLog.empty:
            eventLog = eventLog.sort_values(by=[self.__caseIDColName, self.__constantEventNr])
        return eventLog
        

    #Computes a distance matrix between all sequences using Levenshtein distance.
    def __generateDistanceMatrixSequences(self,sequences):
        distanceMatrix = dict()
        for sequence1 in sequences:
            distanceMatrix[sequence1] = dict()
            for sequence2 in sequences:
                if sequence1 != sequence2:
                    distanceMatrix[sequence1][sequence2] = levenshtein(sequence1,sequence2)
        print("Generated Distance Matrix")
        return distanceMatrix

    #This function calculates the distance between two sequences, sequence1 and sequence2.
    def _getDistanceSequences(self, sequence1, sequence2):
        if sequence1 == "" or sequence2 == "" or sequence1 == sequence2:
            return sys.maxsize
        try:
            distance = self._distanceMatrix[sequence1][sequence2]
        except KeyError:
            print("A Sequence is not in the distance matrix")
            print(sequence1)
            print(sequence2)
            raise
        return distance

    #This function checks if all values in a given distribution are the same.
    def __areAllValuesInDistributionAreTheSame(self, distribution):
        if max(distribution) == min(distribution):
            return True
        else:
            return False

    #This function checks if a distribution violates stochastic t-closeness based on the given equivalence class distribution, overall distribution, and threshold t
    def _violatesStochasticTCloseness(self,distributionEquivalenceClass,overallDistribution,t,activity):
        if activity not in self.__haveAllValuesInActivitityDistributionTheSameValue.keys():
            self.__haveAllValuesInActivitityDistributionTheSameValue[activity] = self.__areAllValuesInDistributionAreTheSame(overallDistribution)
        if not self.__haveAllValuesInActivitityDistributionTheSameValue[activity]:
            upperLimitsBuckets = self._getBucketLimits(t,overallDistribution)
            return (self._calculateStochasticTCloseness(overallDistribution, distributionEquivalenceClass, upperLimitsBuckets) > t)
        else:
            return False

    #calculates the stochastic t-closeness between the overall distribution and the equivalence class distribution using upper limit buckets.
    def _calculateStochasticTCloseness(self, overallDistribution, equivalenceClassDistribution, upperLimitBuckets):
        overallDistribution.sort()
        equivalenceClassDistribution.sort()
        counterOverallDistribution = 0
        counterEquivalenceClass = 0
        distances = list()
        for bucket in upperLimitBuckets:
            lastCounterOverallDistribution = counterOverallDistribution
            lastCounterEquivalenceClass = counterEquivalenceClass
            while counterOverallDistribution<len(overallDistribution) and overallDistribution[counterOverallDistribution
            ] < bucket:
                counterOverallDistribution = counterOverallDistribution + 1
            while counterEquivalenceClass<len(equivalenceClassDistribution) and equivalenceClassDistribution[counterEquivalenceClass
            ] < bucket:
                counterEquivalenceClass = counterEquivalenceClass + 1
            probabilityOfBucketInEQ = (counterEquivalenceClass-lastCounterEquivalenceClass)/len(equivalenceClassDistribution)
            probabilityOfBucketInOverallDistribution = (counterOverallDistribution-lastCounterOverallDistribution)/len(overallDistribution)
            if probabilityOfBucketInEQ == 0 and probabilityOfBucketInOverallDistribution == 0:
                distances.append(0)
            elif probabilityOfBucketInOverallDistribution == 0 or probabilityOfBucketInEQ == 0:
                distances.append(sys.maxsize)
            else:
                distances.append(max(probabilityOfBucketInEQ/probabilityOfBucketInOverallDistribution,probabilityOfBucketInOverallDistribution/probabilityOfBucketInEQ))
        return max(distances)

    #the bucket limits for stochastic t-closeness (used in StochasticTCloseness).
    def _getBucketLimits(self,t,overallDistribution):
        numberOfBuckets = round(t+1)
        overallDistribution.sort()
        divider = round(len(overallDistribution)/numberOfBuckets)
        upperLimitsBuckets = list()
        for i in range(1,numberOfBuckets):
            upperLimitsBuckets.append(overallDistribution[min(round(i*divider),len(overallDistribution)-1)])
        return upperLimitsBuckets