package com.yourorg.netanalysis.ml;

import smile.classification.RandomForest;
import smile.data.DataFrame;
import smile.data.formula.Formula;
import smile.data.vector.DoubleVector;
import smile.data.vector.IntVector;

public class ModelTrainer {

    /**
     * Train a RandomForest model with feature matrix X and labels y.
     *
     * @param X feature matrix (rows = samples, cols = features)
     * @param y class labels (length must equal rows in X)
     * @return trained RandomForest model
     */
    public RandomForest train(double[][] X, int[] y) {
        if (X == null || y == null) {
            throw new IllegalArgumentException("X and y must not be null");
        }
        if (X.length == 0) {
            throw new IllegalArgumentException("X must not be empty");
        }
        if (X.length != y.length) {
            throw new IllegalArgumentException("X row count and y length must match");
        }

        // Build feature columns
        int numFeatures = X[0].length;
        DoubleVector[] featureVectors = new DoubleVector[numFeatures];

        for (int j = 0; j < numFeatures; j++) {
            double[] column = new double[X.length];
            for (int i = 0; i < X.length; i++) {
                column[i] = X[i][j];
            }
            featureVectors[j] = DoubleVector.of("f" + j, column);
        }

        // Label column
        IntVector labels = IntVector.of("label", y);

        // Combine all columns into one DataFrame
        DataFrame features = DataFrame.of(featureVectors);
        DataFrame df = features.merge(labels);

        // Train RandomForest with 100 trees
        return RandomForest.fit(Formula.lhs("label"), df, 100);
    }
}
