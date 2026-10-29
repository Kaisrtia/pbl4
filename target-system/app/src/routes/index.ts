import { Router } from 'express';
import { authRouter } from './auth.routes';
import { resourceRouter } from './resource.routes';
import { defenseRouter } from './defense.routes';
import { simulationRouter } from './simulation.routes';

export const apiRouter = Router();

apiRouter.use('/', defenseRouter);
apiRouter.use('/', authRouter);
apiRouter.use('/', simulationRouter);
apiRouter.use('/resources', resourceRouter);
